package user

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// User is the wire representation of a user (no password fields).
type User struct {
	ID          uint64  `json:"id"`
	Username    string  `json:"username"`
	Role        string  `json:"role"`
	IsActive    bool    `json:"is_active"`
	LastLoginAt *string `json:"last_login_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// CreateUserRequest is the payload accepted by POST /v1/users.
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=1,max=128"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Role     string `json:"role"     validate:"required,oneof=viewer operator admin"`
}

// ChangeRoleRequest is the payload accepted by PATCH /v1/users/{id}/role.
type ChangeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=viewer operator admin"`
}

// ResetPasswordRequest is the payload accepted by PATCH /v1/users/{id}/password.
type ResetPasswordRequest struct {
	Password string `json:"password" validate:"required,min=8,max=128"`
}

// SetActiveRequest is the payload accepted by PATCH /v1/users/{id}/active.
type SetActiveRequest struct {
	Active bool `json:"active"`
}

// ListResponse is the wire format of GET /v1/users.
type ListResponse struct {
	Page  uint64 `json:"page"`
	Limit uint64 `json:"limit"`
	Total uint64 `json:"total"`
	Users []User `json:"users"`
}

// IsValid validates user creation request.
func (r *CreateUserRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate create user request: %w", err)
	}

	return nil
}

// IsValid validates role change request.
func (r *ChangeRoleRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate change role request: %w", err)
	}

	return nil
}

// IsValid validates set-active request.
func (r *SetActiveRequest) IsValid() error { return nil }

// IsValid validates password reset request.
func (r *ResetPasswordRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate reset password request: %w", err)
	}

	return nil
}
