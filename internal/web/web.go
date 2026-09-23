package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist/*
var files embed.FS

// contentTypeByExt covers the few extensions Go's mime table does not know
// about. A manifest served as application/octet-stream is ignored by Chrome,
// which silently breaks PWA installation.
var contentTypeByExt = map[string]string{
	".webmanifest": "application/manifest+json",
	".js":          "text/javascript; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
}

func Handler() http.Handler {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "." || clean == "" {
			clean = "index.html"
		}
		if _, err := fs.Stat(sub, clean); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/index.html"
		}

		// http.ServeContent only sniffs a content type when the header is still
		// empty, so setting it here takes precedence.
		if ctype, ok := contentTypeByExt[strings.ToLower(path.Ext(clean))]; ok {
			w.Header().Set("Content-Type", ctype)
		}

		// The service worker must be allowed to control the whole origin, and it
		// has to be revalidated so an upgraded binary ships a new worker.
		if clean == "sw.js" {
			w.Header().Set("Service-Worker-Allowed", "/")
		}

		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fileServer.ServeHTTP(w, r)
	})
}
