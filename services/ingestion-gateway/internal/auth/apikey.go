package auth

import (
	"crypto/subtle"
	"net/http"
)

// APIKey authenticates requests using the X-API-Key header.
type APIKey struct {
	keys []string
}

func NewAPIKey(keys []string) *APIKey {
	return &APIKey{keys: keys}
}

func (a *APIKey) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-API-Key")
		if provided == "" || !a.valid(provided) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *APIKey) valid(provided string) bool {
	for _, key := range a.keys {
		if subtle.ConstantTimeCompare([]byte(provided), []byte(key)) == 1 {
			return true
		}
	}
	return false
}
