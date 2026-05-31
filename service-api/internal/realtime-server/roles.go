package realtimeserver

import (
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
)

const defaultWSAllowedRoles = "viewer,operator,admin"

func parseWSAllowedRoles(raw string) map[auth.Role]struct{} {
	if strings.TrimSpace(raw) == "" {
		raw = defaultWSAllowedRoles
	}

	parts := strings.Split(raw, ",")
	out := make(map[auth.Role]struct{}, len(parts))

	for _, part := range parts {
		role := auth.Role(strings.TrimSpace(part))
		if role == "" {
			continue
		}

		out[role] = struct{}{}
	}

	if len(out) == 0 {
		return map[auth.Role]struct{}{
			auth.RoleViewer:   {},
			auth.RoleOperator: {},
			auth.RoleAdmin:    {},
		}
	}

	return out
}
