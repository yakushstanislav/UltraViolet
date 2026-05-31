package audit

import (
	"context"
	"net/http"
)

type hintCtxKey struct{}

// ResourceHint is an optional short resource identifier (no secrets) attached
// by handlers for richer audit rows (e.g. onvif:ip:port:command).
type ResourceHint struct {
	Value string
}

// WithResourceHint returns r wrapped so handlers can record ResourceHint via
// HintFor(r).Set(...). The audit Middleware must wrap POST requests with this
// before calling the next handler.
func WithResourceHint(r *http.Request) *http.Request {
	box := &ResourceHint{}

	return r.WithContext(context.WithValue(r.Context(), hintCtxKey{}, box))
}

// HintFor returns the ResourceHint box stored on the request, or nil.
func HintFor(r *http.Request) *ResourceHint {
	v, ok := r.Context().Value(hintCtxKey{}).(*ResourceHint)
	if !ok {
		return nil
	}

	return v
}

// Set assigns the audit resource hint (truncation is the caller's duty).
func (h *ResourceHint) Set(value string) {
	if h == nil {
		return
	}

	h.Value = value
}
