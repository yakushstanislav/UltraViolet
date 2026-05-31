package auth

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// LoginRequest is the payload accepted by POST /v1/auth/login.
type LoginRequest struct {
	Username string `json:"username" validate:"required,max=128"`
	Password string `json:"password" validate:"required,max=256"`
}

// IsValid validates login request fields.
func (r LoginRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate login request: %w", err)
	}

	return nil
}

// RefreshRequest is the payload accepted by refresh/logout endpoints.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,max=2048"`
}

// IsValid validates refresh request fields.
func (r RefreshRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate refresh request: %w", err)
	}

	return nil
}
