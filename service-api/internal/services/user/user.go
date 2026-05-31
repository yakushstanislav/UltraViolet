package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	userdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/user"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	refreshtokenrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/refreshtoken"
	userrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/user"
)

// minBootstrapPasswordLength is the minimum acceptable bootstrap password
// when APP_ENV=production. Below this it is trivial to brute-force even
// behind a rate limiter.
const minBootstrapPasswordLength = 8

// BootstrapConfig holds the credentials used to seed an empty database with
// the first administrative account.
type BootstrapConfig struct {
	Username string
	Password string
	Role     string
}

// Service exposes user-provisioning operations used by main and admin flows.
type Service struct {
	users         userrepository.Repository
	refreshTokens refreshtokenrepository.Repository
	logger        *zap.SugaredLogger
}

// NewService builds a Service.
func NewService(
	users userrepository.Repository,
	refreshTokens refreshtokenrepository.Repository,
	logger *zap.SugaredLogger,
) *Service {
	return &Service{
		users:         users,
		refreshTokens: refreshTokens,
		logger:        logger,
	}
}

// revokeUserSessions revokes every active refresh token for the user so that
// the next refresh round-trip kicks them out. Best-effort: a logged warning
// is preferable to failing the calling mutation, since the underlying state
// change (password / role / active flag) has already succeeded.
//
// This does NOT invalidate already-issued access tokens, which are stateless
// JWTs valid until their `exp`. Tightening that would require either a much
// shorter access TTL or a token-version claim re-checked in the auth middleware.
func (s *Service) revokeUserSessions(ctx context.Context, userID uint64, reason string) {
	if s.refreshTokens == nil {
		return
	}

	revoked, err := s.refreshTokens.RevokeByUserID(ctx, userID)
	if err != nil {
		if s.logger != nil {
			s.logger.Warnw("Can't revoke refresh tokens",
				zap.Uint64("user_id", userID),
				zap.String("reason", reason),
				zap.Error(err),
			)
		}

		return
	}

	if revoked > 0 && s.logger != nil {
		s.logger.Infow("Revoked refresh tokens",
			zap.Uint64("user_id", userID),
			zap.String("reason", reason),
			zap.Int64("revoked", revoked),
		)
	}
}

// EnsureBootstrap creates the seed user when the user table is empty.
//
// When APP_ENV=production (the default outside developer machines) it
// rejects the literal admin/admin pair and any password shorter than
// minBootstrapPasswordLength. APP_ENV=development relaxes both checks
// so a freshly-cloned repo still comes up with admin/admin.
func (s *Service) EnsureBootstrap(ctx context.Context, cfg BootstrapConfig) error {
	count, err := s.users.Count(ctx)
	if err != nil {
		return fmt.Errorf("can't count existing users: %w", err)
	}

	if count > 0 {
		return nil
	}

	if cfg.Username == "" || cfg.Password == "" || cfg.Role == "" {
		return errors.New(
			"bootstrap credentials are empty: " +
				"set AUTH_BOOTSTRAP_USERNAME, AUTH_BOOTSTRAP_PASSWORD, AUTH_BOOTSTRAP_ROLE",
		)
	}

	if isProductionEnv() {
		if cfg.Password == "admin" {
			return errors.New(
				"AUTH_BOOTSTRAP_PASSWORD=admin is not allowed when APP_ENV=production; " +
					"pick a passphrase of at least 8 characters",
			)
		}

		if len(cfg.Password) < minBootstrapPasswordLength {
			return fmt.Errorf(
				"AUTH_BOOTSTRAP_PASSWORD must be at least %d characters when APP_ENV=production",
				minBootstrapPasswordLength,
			)
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("can't hash bootstrap password: %w", err)
	}

	_, err = s.users.Create(ctx, &userrepository.User{
		Username:     cfg.Username,
		PasswordHash: string(hashedPassword),
		Role:         cfg.Role,
		IsActive:     true,
	})
	if err != nil {
		return fmt.Errorf("can't create bootstrap user: %w", err)
	}

	return nil
}

// List returns a paginated user list without password fields.
func (s *Service) List(ctx context.Context, page, limit, offset uint64, q, role string) (*userdto.ListResponse, error) {
	items, total, err := s.users.List(ctx, limit, offset, q, role)
	if err != nil {
		return nil, err
	}

	out := make([]userdto.User, 0, len(items))
	for _, item := range items {
		out = append(out, *userToDTO(item))
	}

	return &userdto.ListResponse{
		Page:  page,
		Limit: limit,
		Total: total,
		Users: out,
	}, nil
}

// GetByID returns one user without password fields.
func (s *Service) GetByID(ctx context.Context, id uint64) (*userdto.User, error) {
	item, err := s.users.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return userToDTO(item), nil
}

// Create provisions a new user account.
func (s *Service) Create(ctx context.Context, req *userdto.CreateUserRequest) (*userdto.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("can't hash password: %w", err)
	}

	id, err := s.users.Create(ctx, &userrepository.User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		Role:         req.Role,
		IsActive:     true,
	})
	if err != nil {
		if errors.Is(err, pgkit.ErrUniqueViolation) {
			return nil, fmt.Errorf("username already exists: %w", ErrUsernameTaken)
		}

		return nil, err
	}

	return s.GetByID(ctx, id)
}

// ChangeRole updates a user's RBAC role.
func (s *Service) ChangeRole(ctx context.Context, id uint64, role string) (*userdto.User, error) {
	actorID := auth.UserIDFromContext(ctx)

	if actorID == id {
		return nil, policyError("cannot change your own role")
	}

	if err := s.users.UpdateRoleSafe(ctx, id, role); err != nil {
		if errors.Is(err, userrepository.ErrLastAdmin) {
			return nil, policyError("cannot remove the last remaining admin")
		}

		return nil, err
	}

	s.revokeUserSessions(ctx, id, "role_change")

	return s.GetByID(ctx, id)
}

// SetActive enables or disables a user account.
func (s *Service) SetActive(ctx context.Context, id uint64, active bool) (*userdto.User, error) {
	actorID := auth.UserIDFromContext(ctx)

	if actorID == id && !active {
		return nil, policyError("cannot deactivate your own account")
	}

	if err := s.users.UpdateActiveSafe(ctx, id, active); err != nil {
		if errors.Is(err, userrepository.ErrLastAdmin) {
			return nil, policyError("cannot remove the last remaining admin")
		}

		return nil, err
	}

	if !active {
		s.revokeUserSessions(ctx, id, "account_deactivated")
	}

	return s.GetByID(ctx, id)
}

// ResetPassword replaces a user's password hash.
func (s *Service) ResetPassword(ctx context.Context, id uint64, password string) error {
	if _, err := s.users.GetByID(ctx, id); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("can't hash password: %w", err)
	}

	if err := s.users.UpdatePassword(ctx, id, string(hashedPassword)); err != nil {
		return err
	}

	s.revokeUserSessions(ctx, id, "password_reset")

	return nil
}

// Delete soft-disables a user account.
func (s *Service) Delete(ctx context.Context, id uint64) error {
	actorID := auth.UserIDFromContext(ctx)

	if actorID == id {
		return policyError("cannot delete your own account")
	}

	if err := s.users.UpdateActiveSafe(ctx, id, false); err != nil {
		if errors.Is(err, userrepository.ErrLastAdmin) {
			return policyError("cannot remove the last remaining admin")
		}

		return err
	}

	s.revokeUserSessions(ctx, id, "account_deleted")

	return nil
}

// isProductionEnv returns true unless APP_ENV is explicitly set to
// "development" (case-insensitive). Empty APP_ENV is treated as
// production so a misconfigured deployment fails closed.
func isProductionEnv() bool {
	value := strings.TrimSpace(os.Getenv("APP_ENV"))

	return !strings.EqualFold(value, "development")
}

func userToDTO(item *userrepository.User) *userdto.User {
	dto := &userdto.User{
		ID:        item.ID,
		Username:  item.Username,
		Role:      item.Role,
		IsActive:  item.IsActive,
		CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: item.UpdatedAt.UTC().Format(time.RFC3339),
	}

	if item.LastLoginAt.Valid {
		formatted := item.LastLoginAt.Time.UTC().Format(time.RFC3339)
		dto.LastLoginAt = &formatted
	}

	return dto
}
