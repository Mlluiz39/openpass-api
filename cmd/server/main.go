package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openpass/api/internal/admin"
	"github.com/openpass/api/internal/apikeys"
	"github.com/openpass/api/internal/audit"
	"github.com/openpass/api/internal/backup"
	"github.com/openpass/api/internal/config"
	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/vault"
	"github.com/openpass/api/internal/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if cfg.GeneratedAdminPassword {
		log.Printf("OPENPASS_ADMIN_PASSWORD not set; temporary admin password: %s", cfg.AdminPassword)
	}

	database, err := opdb.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()
	if err := opdb.Migrate(database, opdb.CoreSchema); err != nil {
		log.Fatal(err)
	}

	adminSvc := admin.New(database, cfg.AdminPassword, cfg.SecretKey)
	if cfg.ResetAdminPassword {
		if err := adminSvc.ResetPassword(); err != nil {
			log.Fatalf("failed to reset admin password: %v", err)
		}
		log.Printf("OPENPASS_ADMIN_PASSWORD_RESET set; admin password replaced by OPENPASS_ADMIN_PASSWORD")
	}
	auditSvc := audit.New(database)
	keySvc := apikeys.New(database, cfg.SecretKey)
	keySvc.SetAudit(auditSvc)
	vaultSvc := vault.New(database, cfg.SecretKey)
	backupSvc := backup.New(database, cfg.SecretKey)

	mux := http.NewServeMux()
	adminSvc.RegisterRoutes(mux)
	keySvc.RegisterAdminRoutes(mux, adminSvc.Require)
	keySvc.RegisterAPIRoutes(mux)
	auditSvc.RegisterAdminRoutes(mux, adminSvc.Require)
	backupSvc.RegisterAdminRoutes(mux, adminSvc.Require)
	vaultSvc.RegisterAdminRoutes(mux, adminSvc.Require)
	vaultSvc.RegisterAPIRoutes(mux, keySvc)
	registerBackupRoutes(mux, backupSvc, keySvc)
	mux.Handle("/", web.Handler())

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		log.Printf("OpenPass API + CRM panel listening on %s", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		log.Fatal(err)
	case <-stop:
		log.Printf("Shutdown signal received, draining connections...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Forced shutdown: %v", err)
		}
		log.Printf("Server stopped")
	}
}

func registerBackupRoutes(mux *http.ServeMux, backups *backup.Service, keys *apikeys.Service) {
	mux.Handle("POST /api/v1/backup/create", keys.RequirePermission("backup:create", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, err := backups.Export(r.Context(), r.URL.Query().Get("password"))
		if err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "backup_export_failed")
			return
		}
		w.Header().Set("Content-Type", backup.MIMEType)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.Filename))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(file.Content)
	})))

	mux.Handle("POST /api/v1/backup/restore", keys.RequirePermission("backup:restore", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
			Backup   string `json:"backup"`
		}
		if err := httpjson.Decode(r, &body); err != nil {
			httpjson.Error(w, http.StatusBadRequest, "invalid_json")
			return
		}
		if err := backups.Restore(r.Context(), []byte(body.Backup), body.Password); err != nil {
			httpjson.Error(w, http.StatusBadRequest, "backup_restore_failed")
			return
		}
		httpjson.Write(w, http.StatusOK, map[string]any{"restored": true})
	})))
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, recorder.status, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
