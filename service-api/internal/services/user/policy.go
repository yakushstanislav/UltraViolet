package user

import (
	"errors"
	"fmt"
	"strings"
)

// ErrPolicyViolation is returned when an admin action would break safety rules.
var ErrPolicyViolation = errors.New("user policy violation")

// ErrUsernameTaken is returned when a new account username is already in use.
var ErrUsernameTaken = errors.New("username already taken")

// PolicyViolationAPIReason maps policy errors to stable wire reasons.
func PolicyViolationAPIReason(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()

	switch {
	case strings.Contains(msg, "cannot change your own role"):
		return "cannot_change_own_role"
	case strings.Contains(msg, "cannot deactivate your own account"):
		return "cannot_deactivate_self"
	case strings.Contains(msg, "cannot delete your own account"):
		return "cannot_delete_self"
	case strings.Contains(msg, "last remaining admin"):
		return "last_admin_protected"
	default:
		return "user_policy_violation"
	}
}

func policyError(format string, args ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), ErrPolicyViolation)
}
