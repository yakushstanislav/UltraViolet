package search

import (
	"errors"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/apireason"
)

// InvalidFiltersAPIReason maps a search filter error chain to a stable wire reason.
func InvalidFiltersAPIReason(err error) string {
	if err == nil {
		return apireason.SearchInvalidFilters
	}

	s := err.Error()

	switch {
	case strings.Contains(s, "invalid port_from"):
		return apireason.SearchInvalidPortFrom
	case strings.Contains(s, "invalid port_to"):
		return apireason.SearchInvalidPortTo
	case strings.Contains(s, "invalid port"):
		return apireason.SearchInvalidPort
	case strings.Contains(s, "invalid asn"):
		return apireason.SearchInvalidASN
	case strings.Contains(s, "invalid last_seen_from"):
		return apireason.SearchInvalidLastSeenFrom
	case strings.Contains(s, "invalid last_seen_to"):
		return apireason.SearchInvalidLastSeenTo
	case strings.Contains(s, "invalid risk_score_min"):
		return apireason.SearchInvalidRiskScoreMin
	case strings.Contains(s, "invalid risk_score_max"):
		return apireason.SearchInvalidRiskScoreMax
	case strings.Contains(s, "invalid cve_severity"):
		return apireason.SearchInvalidCVESeverity
	case strings.Contains(s, "can't validate search request"):
		return apireason.SearchRequestValidationFailed
	case errors.Is(err, ErrInvalidFilters):
		return apireason.SearchInvalidFilters
	default:
		return apireason.SearchInvalidFilters
	}
}
