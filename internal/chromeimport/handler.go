package chromeimport

import (
	"net/http"

	"github.com/openpass/api/internal/admin"
	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/vault"
)

// request is the JSON body of POST /api/admin/import/chrome.
//
// csv holds the raw contents of the file Chrome's password manager exports
// ("Baixar arquivo"). Transferring the file in the body (over HTTPS) keeps it
// off the server's disk entirely.
type request struct {
	CSV       string `json:"csv"`
	VaultName string `json:"vault"`
	DryRun    bool   `json:"dry_run"`
}

// Handler imports a Chrome password export into the caller's vault.
//
// It is registered behind admin.Require, so the entries always land in the
// session user's own vault — an admin importing a file can never write into
// somebody else's data.
func Handler(svc *vault.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := admin.FromContext(r.Context())
		if !ok {
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var input request
		if err := httpjson.Decode(r, &input); err != nil {
			httpjson.Error(w, http.StatusBadRequest, "invalid_json")
			return
		}
		if len(input.CSV) == 0 {
			httpjson.Error(w, http.StatusBadRequest, "csv_required")
			return
		}
		if len(input.CSV) > 8<<20 {
			httpjson.Error(w, http.StatusRequestEntityTooLarge, "csv_too_large")
			return
		}

		res, err := Import(r.Context(), svc, user.ID, input.CSV, Options{
			VaultName: input.VaultName,
			DryRun:    input.DryRun,
		})
		if err != nil {
			httpjson.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		httpjson.Write(w, http.StatusOK, res)
	})
}
