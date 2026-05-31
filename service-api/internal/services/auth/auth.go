package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	pkgauth "github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/refreshtoken"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/user"
)

// ErrUnauthorized is returned for any invalid-credentials path. Callers map
// it to HTTP 401 without leaking which sub-check failed.
var ErrUnauthorized = errors.New("unauthorized")

// dummyBcryptHash is a precomputed bcrypt of an unguessable string. We compare
// against it for unknown usernames so the login path takes the same time
// regardless of whether the account exists.
const dummyBcryptHash = "$2a$10$Dwn9I0JpOk2.zS7dN9d4heX0IsPj/xq8KZb1aV9V0V8i3R5wU4uYS"

// TokenPair is the access/refresh token bundle returned to clients on
// successful authentication.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	Role         string
}

// Service orchestrates user-credential validation and refresh-token rotation.
type Service struct {
	users  user.Repository
	tokens refreshtoken.Repository
	cfg    pkgauth.Config
	nowFn  func() time.Time
}

// NewService builds an auth Service.
func NewService(users user.Repository, tokens refreshtoken.Repository, cfg pkgauth.Config) *Service {
	return &Service{
		users:  users,
		tokens: tokens,
		cfg:    cfg,
		nowFn:  func() time.Time { return time.Now().UTC() },
	}
}

// Login validates credentials with a constant-time path and returns a fresh token pair.
func (s *Service) Login(ctx context.Context, username, password string) (TokenPair, error) {
	u, lookupErr := s.users.GetByUsername(ctx, username)

	passwordHash := dummyBcryptHash
	accountUsable := false

	if lookupErr == nil && u != nil && u.IsActive {
		passwordHash = u.PasswordHash
		accountUsable = true
	}

	cmpErr := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if !accountUsable || cmpErr != nil {
		return TokenPair{}, ErrUnauthorized
	}

	pair, err := s.issueTokenPair(ctx, u.ID, pkgauth.Role(u.Role))
	if err != nil {
		return TokenPair{}, err
	}

	_ = s.users.TouchLastLogin(ctx, u.ID, s.nowFn())

	return pair, nil
}

// Refresh rotates the supplied refresh token and issues a fresh token pair.
//
// The consume-and-insert step runs in a single repository transaction
// (RotateByHash), so a transient DB failure during issuance leaves the
// caller's old refresh token still valid and a retry is safe. Pre-flight
// checks (user active) happen before the rotation; the user is looked up
// via the active session row so we don't need to trust the caller's claim
// about which account the token belongs to.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	oldHash := HashToken(refreshToken)

	session, err := s.tokens.GetActiveByHash(ctx, oldHash)
	if err != nil {
		return TokenPair{}, ErrUnauthorized
	}

	u, err := s.users.GetByID(ctx, session.UserID)
	if err != nil || u == nil || !u.IsActive {
		return TokenPair{}, ErrUnauthorized
	}

	accessToken, err := pkgauth.GenerateAccessToken(s.cfg.JWTSecret, s.cfg.AccessTTL, u.ID, pkgauth.Role(u.Role))
	if err != nil {
		return TokenPair{}, fmt.Errorf("can't issue access token: %w", err)
	}

	refreshRaw, err := generateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}

	replacement := &refreshtoken.RefreshToken{
		UserID:    u.ID,
		TokenHash: HashToken(refreshRaw),
		ExpiresAt: s.nowFn().Add(s.cfg.RefreshTTL),
	}

	if _, _, err := s.tokens.RotateByHash(ctx, oldHash, replacement); err != nil {
		// "Old token was already consumed / does not exist" → 401 so the
		// client re-logs in. Every other error is transient (DB blip, etc.):
		// surface it so the handler returns 5xx and the client can retry
		// with the same refresh token — the rotation TX rolled back, so the
		// old session is still valid.
		if errors.Is(err, pgkit.ErrNoRows) {
			return TokenPair{}, ErrUnauthorized
		}

		return TokenPair{}, fmt.Errorf("can't rotate refresh token: %w", err)
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshRaw,
		Role:         u.Role,
	}, nil
}

// Logout revokes the refresh token if it's still active.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	session, err := s.tokens.GetActiveByHash(ctx, HashToken(refreshToken))
	if err != nil {
		return ErrUnauthorized
	}

	if err := s.tokens.RevokeByID(ctx, session.ID); err != nil {
		return fmt.Errorf("can't revoke refresh token: %w", err)
	}

	return nil
}

func (s *Service) issueTokenPair(ctx context.Context, userID uint64, role pkgauth.Role) (TokenPair, error) {
	accessToken, err := pkgauth.GenerateAccessToken(s.cfg.JWTSecret, s.cfg.AccessTTL, userID, role)
	if err != nil {
		return TokenPair{}, fmt.Errorf("can't issue access token: %w", err)
	}

	refreshRaw, err := generateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}

	_, err = s.tokens.Create(ctx, &refreshtoken.RefreshToken{
		UserID:    userID,
		TokenHash: HashToken(refreshRaw),
		ExpiresAt: s.nowFn().Add(s.cfg.RefreshTTL),
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("can't store refresh token: %w", err)
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshRaw,
		Role:         string(role),
	}, nil
}

func generateOpaqueToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("can't generate random token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// HashToken returns the lookup hash used to store refresh tokens at rest.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
