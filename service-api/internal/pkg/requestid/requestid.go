package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/gofrs/uuid/v5"
)

type requestIDContextKey struct{}

// New generates a fresh request id. Falls back to a random hex string when
// uuid.NewV4 fails so logs always carry a non-empty correlation id.
func New() string {
	id, err := uuid.NewV4()
	if err == nil {
		return id.String()
	}

	var buf [16]byte

	if _, randErr := rand.Read(buf[:]); randErr != nil {
		return "00000000-0000-0000-0000-000000000000"
	}

	return hex.EncodeToString(buf[:])
}

// PackContext attaches the request id to the context.
func PackContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// UnpackContext returns the request id from context, or empty string if missing.
func UnpackContext(ctx context.Context) string {
	requestID, ok := ctx.Value(requestIDContextKey{}).(string)
	if !ok {
		return ""
	}

	return requestID
}
