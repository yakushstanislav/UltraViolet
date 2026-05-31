package user

import (
	"errors"
	"strings"

	"gopkg.in/go-playground/validator.v9"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/apireason"
)

// ValidationAPIReason maps a user request validation error to a stable wire reason.
func ValidationAPIReason(err error) string {
	if err == nil {
		return apireason.UserInvalidInput
	}

	var validationErrors validator.ValidationErrors

	if errors.As(err, &validationErrors) {
		for _, fieldError := range validationErrors {
			switch fieldError.Field() {
			case "Username":
				return apireason.UserUsernameInvalid
			case "Password":
				return apireason.UserPasswordInvalid
			case "Role":
				return apireason.UserRoleInvalid
			}
		}
	}

	s := err.Error()

	switch {
	case strings.Contains(s, "CreateUserRequest.Username"),
		strings.Contains(s, "Field validation for 'Username'"):
		return apireason.UserUsernameInvalid
	case strings.Contains(s, "CreateUserRequest.Password"),
		strings.Contains(s, "ResetPasswordRequest.Password"),
		strings.Contains(s, "Field validation for 'Password'"):
		return apireason.UserPasswordInvalid
	case strings.Contains(s, "CreateUserRequest.Role"),
		strings.Contains(s, "ChangeRoleRequest.Role"),
		strings.Contains(s, "Field validation for 'Role'"):
		return apireason.UserRoleInvalid
	default:
		return apireason.UserInvalidInput
	}
}
