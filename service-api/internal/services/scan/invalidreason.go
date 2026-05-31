package scan

import (
	"errors"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/apireason"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanpolicy"
)

// InvalidInputAPIReason maps a scan Create error chain to a stable wire reason.
func InvalidInputAPIReason(err error) string {
	if err == nil {
		return apireason.ScanInvalidInput
	}

	s := err.Error()

	switch {
	case strings.Contains(s, "masscan and zmap require IPv4 targets"):
		return apireason.ScanSynEngineIPv4Required
	case strings.Contains(s, "limit is required and must be > 0 for random strategy"):
		return apireason.ScanRandomLimitRequired
	case strings.Contains(s, "random strategy requires SCAN_ALLOWED_CIDRS to be configured"):
		return apireason.ScanRandomAllowedCIDRsUnconfigured
	case strings.Contains(s, "limit is required and must be > 0 for country strategy"):
		return apireason.ScanCountryLimitRequired
	case strings.Contains(s, "country strategy requires GeoIP country database"):
		return apireason.ScanCountryGeoIPRequired
	case strings.Contains(s, "has no IPv4 prefixes in GeoIP database"):
		return apireason.ScanCountryNoPrefixes
	case strings.Contains(s, "limit exceeds SCAN_MAX_HOSTS policy"):
		return apireason.ScanRandomLimitExceedsMaxHosts
	case strings.Contains(s, "target is empty"):
		return apireason.ScanTargetEmpty
	case strings.Contains(s, "can't resolve target host"):
		return apireason.ScanTargetResolveFailed
	case strings.Contains(s, "target host resolved to no valid IP addresses"):
		return apireason.ScanTargetResolveEmpty
	case strings.Contains(s, scanpolicy.ErrCIDRNotAllowed.Error()):
		return apireason.ScanCIDRNotAllowed
	case strings.Contains(s, scanpolicy.ErrTooManyPorts.Error()):
		return apireason.ScanTooManyPorts
	case strings.Contains(s, scanpolicy.ErrTooManyHosts.Error()):
		return apireason.ScanTooManyHosts
	case strings.Contains(s, scanpolicy.ErrInvalidCIDR.Error()):
		return apireason.ScanInvalidCIDR
	case strings.Contains(s, "ports expression is empty"):
		return apireason.ScanPortsExprEmpty
	case strings.Contains(s, "ports expression has no ports"):
		return apireason.ScanPortsExprNoPorts
	case strings.Contains(s, "invalid port range bounds"):
		return apireason.ScanPortsInvalidRangeBounds
	case strings.Contains(s, "invalid port"):
		return apireason.ScanInvalidPort
	case strings.Contains(s, "can't validate create scan ports expression"):
		return apireason.ScanPortsExprInvalid
	case strings.Contains(s, "can't validate create scan request"):
		return apireason.ScanInvalidInput
	case errors.Is(err, ErrInvalidInput):
		return apireason.ScanInvalidInput
	default:
		return apireason.ScanInvalidInput
	}
}
