package bitwarden

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/openpass/api/internal/secure"
)

func sha256Hex(value string) string {
	return secure.SHA256Hex(value)
}

// writeMessage renders the upstream error shape: HTTP status + a `message`
// body. Clients surface `message` verbatim to the user.
func writeMessage(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"message": message})
}

// writeGrantError renders the OAuth-style error used by the identity
// endpoint (`{"error": "invalid_grant", ...}`).
func writeGrantError(w http.ResponseWriter, status int, description string, extra map[string]any) {
	body := map[string]any{
		"error":             "invalid_grant",
		"error_description": description,
	}
	for key, value := range extra {
		body[key] = value
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

// decodeJSON decodes a request body tolerating unknown fields: the clients
// send many fields this server does not use, and ignoring them (instead of
// failing) keeps old and new client versions working against one backend.
func decodeJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 32<<20))
	return decoder.Decode(dst)
}

// formValues merges the URL query with a form-encoded body, including for
// methods whose body the standard library does not parse (DELETE).
func formValues(r *http.Request) url.Values {
	values, _ := url.ParseQuery(r.URL.RawQuery)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil {
			if bodyValues, err := url.ParseQuery(string(body)); err == nil {
				for key, vals := range bodyValues {
					values[key] = append(values[key], vals...)
				}
			}
		}
	}
	return values
}

// idsFromRequest reads the `ids` parameter of the bulk endpoints, which the
// clients send either in the query string or form body, comma-separated.
func idsFromRequest(r *http.Request) []string {
	raw := formValues(r).Get("ids")
	var out []string
	for _, id := range strings.Split(raw, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}
