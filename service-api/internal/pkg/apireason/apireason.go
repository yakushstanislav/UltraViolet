// Package apireason defines stable machine-readable JSON "reason" values for
// HTTP 400 invalid_argument responses (i18n keys on the client).
package apireason

// Scan create / policy (POST /v1/scans).
const (
	ScanInvalidInput                   = "scan_invalid_input"
	ScanCIDRNotAllowed                 = "scan_cidr_not_allowed"
	ScanTooManyPorts                   = "scan_too_many_ports"
	ScanTooManyHosts                   = "scan_too_many_hosts"
	ScanInvalidCIDR                    = "scan_invalid_cidr"
	ScanInvalidPort                    = "scan_invalid_port"
	ScanSynEngineIPv4Required          = "scan_syn_engine_ipv4_required"
	ScanTargetEmpty                    = "scan_target_empty"
	ScanTargetResolveFailed            = "scan_target_resolve_failed"
	ScanTargetResolveEmpty             = "scan_target_resolve_empty"
	ScanRandomLimitRequired            = "scan_random_limit_required"
	ScanRandomAllowedCIDRsUnconfigured = "scan_random_allowed_cidrs_unconfigured"
	ScanRandomLimitExceedsMaxHosts     = "scan_random_limit_exceeds_max_hosts"
	ScanPortsExprEmpty                 = "scan_ports_expr_empty"
	ScanPortsExprNoPorts               = "scan_ports_expr_no_ports"
	ScanPortsInvalidRangeBounds        = "scan_ports_invalid_range_bounds"
	ScanPortsExprInvalid               = "scan_ports_expr_invalid"
)

// Scan create / country strategy (POST /v1/scans).
const (
	ScanCountryGeoIPRequired = "scan_country_geoip_required"
	ScanCountryNoPrefixes    = "scan_country_no_prefixes"
	ScanCountryLimitRequired = "scan_country_limit_required"
)

// Scan state transitions (POST /v1/scans/{id}/cancel|pause|resume|restart).
const (
	ScanNotCancelable  = "scan_not_cancelable"
	ScanNotPauseable   = "scan_not_pauseable"
	ScanNotResumable   = "scan_not_resumable"
	ScanNotRestartable = "scan_not_restartable"
)

// Search query (GET /v1/search).
const (
	SearchInvalidFilters          = "search_invalid_filters"
	SearchInvalidPort             = "search_invalid_port"
	SearchInvalidPortFrom         = "search_invalid_port_from"
	SearchInvalidPortTo           = "search_invalid_port_to"
	SearchInvalidASN              = "search_invalid_asn"
	SearchInvalidLastSeenFrom     = "search_invalid_last_seen_from"
	SearchInvalidLastSeenTo       = "search_invalid_last_seen_to"
	SearchInvalidRiskScoreMin     = "search_invalid_risk_score_min"
	SearchInvalidRiskScoreMax     = "search_invalid_risk_score_max"
	SearchInvalidCVESeverity      = "search_invalid_cve_severity"
	SearchRequestValidationFailed = "search_request_validation_failed"
)

// User admin (POST /v1/users, PATCH /v1/users/{id}/password|role).
const (
	UserUsernameInvalid = "user_username_invalid"
	UserPasswordInvalid = "user_password_invalid"
	UserRoleInvalid     = "user_role_invalid"
	UserInvalidInput    = "user_invalid_input"
	UserUsernameTaken   = "user_username_taken"
)
