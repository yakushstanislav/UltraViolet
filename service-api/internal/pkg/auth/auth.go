// Package auth carries the authentication primitives shared between the
// auth service (token issuance) and the HTTP middleware (token validation):
// role enum, JWT config, access-token codec, and request-context helpers.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role defines RBAC role resolved from a bearer token.
type Role string

const (
	// RoleViewer can access read-only API endpoints.
	RoleViewer Role = "viewer"
	// RoleOperator can run operational write actions.
	RoleOperator Role = "operator"
	// RoleAdmin has full access including administrative endpoints.
	RoleAdmin Role = "admin"
)

// Config holds JWT auth settings.
type Config struct {
	JWTSecret  string        `env:"AUTH_JWT_SECRET"  env-required:"true"`
	AccessTTL  time.Duration `env:"AUTH_ACCESS_TTL"  env-default:"15m"`
	RefreshTTL time.Duration `env:"AUTH_REFRESH_TTL" env-default:"168h"`
}

// MinJWTSecretLength is the minimum number of bytes required in
// AUTH_JWT_SECRET. 32 bytes ≈ 128 bits of entropy when hex-encoded, which is
// the floor for HS256 to remain brute-force-resistant; install.sh generates
// 32 random bytes by default.
const MinJWTSecretLength = 32

// Validate fails-fast on weak auth configuration. Called at uv-api startup.
func (c *Config) Validate() error {
	if len(c.JWTSecret) < MinJWTSecretLength {
		return fmt.Errorf("AUTH_JWT_SECRET must be at least %d characters (got %d)", MinJWTSecretLength, len(c.JWTSecret))
	}

	return nil
}

// AccessClaims describes the JWT payload.
type AccessClaims struct {
	Role   Role   `json:"role"`
	UserID uint64 `json:"uid"`
	jwt.RegisteredClaims
}

// GenerateAccessToken creates a signed access JWT.
func GenerateAccessToken(secret string, ttl time.Duration, userID uint64, role Role) (string, error) {
	now := time.Now().UTC()

	claims := AccessClaims{
		Role:   role,
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatUint(userID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("can't sign access token: %w", err)
	}

	return signed, nil
}

// ParseAccessToken validates the raw token and returns its claims. The
// signing method is pinned to HS256 — the same one GenerateAccessToken uses
// — so any alg-confusion attack (HS384/HS512 / RS256 with key-as-secret) is
// rejected before the signature is even checked.
func ParseAccessToken(secret, rawToken string) (*AccessClaims, error) {
	claims := &AccessClaims{}

	token, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

type contextKey string

const (
	roleContextKey   contextKey = "auth_role"
	userIDContextKey contextKey = "auth_user_id"
)

// WithRole attaches the resolved role to the request context.
func WithRole(ctx context.Context, role Role) context.Context {
	return context.WithValue(ctx, roleContextKey, role)
}

// WithUserID attaches the resolved user id to the request context.
func WithUserID(ctx context.Context, userID uint64) context.Context {
	return context.WithValue(ctx, userIDContextKey, userID)
}

// RoleFromContext extracts the role from a request context.
func RoleFromContext(ctx context.Context) Role {
	role, _ := ctx.Value(roleContextKey).(Role)
	return role
}

// UserIDFromContext extracts the user id from a request context.
func UserIDFromContext(ctx context.Context) uint64 {
	userID, _ := ctx.Value(userIDContextKey).(uint64)
	return userID
}
