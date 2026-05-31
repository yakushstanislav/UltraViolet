package host

// DNSRecord is the JSON representation of a resolved DNS record for a host.
type DNSRecord struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Value            string `json:"value"`
	Source           string `json:"source"`
	ForwardConfirmed bool   `json:"forward_confirmed"`
	CapturedAt       string `json:"captured_at"`
}

// Host is the JSON representation of a discovered host.
type Host struct {
	ID            uint64       `json:"id"`
	IP            string       `json:"ip"`
	CountryCode   string       `json:"country_code,omitempty"`
	CountryName   string       `json:"country_name,omitempty"`
	City          string       `json:"city,omitempty"`
	Latitude      *float64     `json:"latitude,omitempty"`
	Longitude     *float64     `json:"longitude,omitempty"`
	ASN           *int64       `json:"asn,omitempty"`
	ASNOrg        string       `json:"asn_org,omitempty"`
	PtrHostname   string       `json:"ptr_hostname,omitempty"`
	FirstSeen     string       `json:"first_seen"`
	LastSeen      string       `json:"last_seen"`
	RiskScore     int          `json:"risk_score"`
	RiskFactors   []RiskFactor `json:"risk_factors,omitempty"`
	RiskUpdatedAt string       `json:"risk_updated_at,omitempty"`
	Page          uint64       `json:"page"`
	Limit         uint64       `json:"limit"`
	Total         uint64       `json:"total"`
	DNS           []DNSRecord  `json:"dns,omitempty"`
	Services      []Service    `json:"services,omitempty"`
}

// SSHInfo is the JSON representation of SSH-level metadata for a service.
type SSHInfo struct {
	ServerVersion      string   `json:"server_version,omitempty"`
	HostKeyType        string   `json:"host_key_type,omitempty"`
	HostKeyFingerprint string   `json:"host_key_fingerprint,omitempty"`
	KexAlgorithms      []string `json:"kex_algorithms,omitempty"`
	HostKeyAlgorithms  []string `json:"host_key_algorithms,omitempty"`
}

// SMTPInfo is the JSON representation of SMTP capability metadata.
type SMTPInfo struct {
	Banner         string   `json:"banner,omitempty"`
	Capabilities   []string `json:"capabilities,omitempty"`
	STARTTLS       bool     `json:"starttls"`
	AuthMethods    []string `json:"auth_methods,omitempty"`
	MaxMessageSize *int64   `json:"max_message_size,omitempty"`
}

// Service is the JSON representation of a discovered listening port.
//
// Fingerprint carries the "primary" detected technology layer (the
// highest-signal component, typically the web server or the database
// product) for backwards compatibility; Fingerprints is the full stack
// returned since the multi-component migration — web_server + cms +
// runtime + js_library together, each with its own product, version,
// detection source and stack role.
type Service struct {
	ID           uint64        `json:"id"`
	Port         uint16        `json:"port"`
	Transport    string        `json:"transport"`
	Protocol     string        `json:"protocol,omitempty"`
	Banner       string        `json:"banner,omitempty"`
	BannerHash   string        `json:"banner_hash,omitempty"`
	LastSeen     string        `json:"last_seen"`
	RiskScore    int           `json:"risk_score"`
	RiskFactors  []string      `json:"risk_factors,omitempty"`
	HTTP         *HTTPResponse `json:"http,omitempty"`
	TLS          *TLSCert      `json:"tls,omitempty"`
	SSH          *SSHInfo      `json:"ssh,omitempty"`
	SMTP         *SMTPInfo     `json:"smtp,omitempty"`
	Fingerprint  *Fingerprint  `json:"fingerprint,omitempty"`
	Fingerprints []Fingerprint `json:"fingerprints,omitempty"`
	CVEs         []ServiceCVE  `json:"cves,omitempty"`
	CVESummary   *CVESummary   `json:"cve_summary,omitempty"`
}

// CVESummary breaks down matched CVE counts per CVSS severity tier.
type CVESummary struct {
	Critical uint64 `json:"critical"`
	High     uint64 `json:"high"`
	Medium   uint64 `json:"medium"`
	Low      uint64 `json:"low"`
}

// ServiceCVE is one CVE attached to a service.
type ServiceCVE struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity,omitempty"`
	CVSSScore      *float64 `json:"cvss_score,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	MatchedVersion string   `json:"matched_version,omitempty"`
	MatchedAt      string   `json:"matched_at"`
	Confidence     *int     `json:"confidence,omitempty"`
}

// SecurityHeaders is the subset of HTTP security headers from a response.
type SecurityHeaders struct {
	HSTS          string `json:"hsts,omitempty"`
	CSP           string `json:"csp,omitempty"`
	XFrameOptions string `json:"x_frame_options,omitempty"`
	XContentType  string `json:"x_content_type_options,omitempty"`
}

// HTTPResponse is the JSON representation of a captured HTTP response.
type HTTPResponse struct {
	StatusCode      *int32             `json:"status_code,omitempty"`
	ServerHeader    string             `json:"server,omitempty"`
	Title           string             `json:"title,omitempty"`
	Headers         map[string]string  `json:"headers,omitempty"`
	Body            string             `json:"body,omitempty"`
	SecurityHeaders *SecurityHeaders   `json:"security_headers,omitempty"`
	SecurityInfo    *HTTPSecurityInfo  `json:"security_info,omitempty"`
	RedirectURL     string             `json:"redirect_url,omitempty"`
	FaviconHash     *int32             `json:"favicon_hash,omitempty"`
	Technologies    []string           `json:"technologies,omitempty"`
	RedirectChain   []HTTPRedirectStep `json:"redirect_chain,omitempty"`
	RobotsTxt       string             `json:"robots_txt,omitempty"`
	SecurityTxt     string             `json:"security_txt,omitempty"`
	BodySHA256      string             `json:"body_sha256,omitempty"`
	NotFoundHash    string             `json:"not_found_hash,omitempty"`
	AltSvcRaw       string             `json:"alt_svc,omitempty"`
	HTTP3Supported  bool               `json:"http3_supported,omitempty"`
	HasScreenshot   bool               `json:"has_screenshot,omitempty"`
	CapturedAt      string             `json:"captured_at"`
}

// HTTPSecurityInfo is the structured form of common HTTP security
// response headers. Sits next to the legacy SecurityHeaders block; new
// frontends should prefer this richer shape.
type HTTPSecurityInfo struct {
	HSTSMaxAge               *int64 `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubdomains    bool   `json:"hsts_include_subdomains,omitempty"`
	HSTSPreload              bool   `json:"hsts_preload,omitempty"`
	CSPPresent               bool   `json:"csp_present,omitempty"`
	CSPHasUnsafeInline       bool   `json:"csp_has_unsafe_inline,omitempty"`
	CSPHasUnsafeEval         bool   `json:"csp_has_unsafe_eval,omitempty"`
	XFrameOptions            string `json:"x_frame_options,omitempty"`
	XContentTypeOptions      string `json:"x_content_type_options,omitempty"`
	ReferrerPolicy           string `json:"referrer_policy,omitempty"`
	PermissionsPolicyPresent bool   `json:"permissions_policy_present,omitempty"`
	CORSAllowOrigin          string `json:"cors_allow_origin,omitempty"`
	CookieSecureCount        int    `json:"cookie_secure_count,omitempty"`
	CookieHTTPOnlyCount      int    `json:"cookie_httponly_count,omitempty"`
	CookieSameSiteStrict     int    `json:"cookie_samesite_strict_count,omitempty"`
	CookieSameSiteLax        int    `json:"cookie_samesite_lax_count,omitempty"`
	CookieSameSiteNone       int    `json:"cookie_samesite_none_count,omitempty"`
}

// HTTPRedirectStep is one hop in the redirect chain.
type HTTPRedirectStep struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location,omitempty"`
}

// TLSCert is the JSON representation of an observed TLS certificate.
type TLSCert struct {
	Subject           string          `json:"subject,omitempty"`
	Issuer            string          `json:"issuer,omitempty"`
	FingerprintSHA256 string          `json:"fingerprint_sha256,omitempty"`
	NotBefore         string          `json:"not_before,omitempty"`
	NotAfter          string          `json:"not_after,omitempty"`
	DaysUntilExpiry   *int            `json:"days_until_expiry,omitempty"`
	SANs              []string        `json:"sans,omitempty"`
	JARMFingerprint   string          `json:"jarm_fingerprint,omitempty"`
	TLSVersion        string          `json:"tls_version,omitempty"`
	CipherSuite       string          `json:"cipher_suite,omitempty"`
	JA3SHash          string          `json:"ja3s_hash,omitempty"`
	JA4SHash          string          `json:"ja4s_hash,omitempty"`
	SecurityGrade     string          `json:"security_grade,omitempty"`
	Findings          []TLSFinding    `json:"findings,omitempty"`
	Chain             []TLSChainEntry `json:"chain,omitempty"`
}

// TLSFinding is one detected security issue against a service's TLS
// handshake (expired cert, weak protocol, hostname mismatch, …).
type TLSFinding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Detail   string `json:"detail,omitempty"`
}

// TLSChainEntry is one node in the certificate chain returned alongside a TLSCert.
type TLSChainEntry struct {
	Position          int      `json:"position"`
	Subject           string   `json:"subject,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	FingerprintSHA256 string   `json:"fingerprint_sha256,omitempty"`
	NotBefore         string   `json:"not_before,omitempty"`
	NotAfter          string   `json:"not_after,omitempty"`
	SANs              []string `json:"sans,omitempty"`
}

// Fingerprint is the JSON representation of one detected technology
// component for a service. Source identifies how the (product, version)
// pair was extracted (HTTP Server header, X-Powered-By, meta generator,
// body pattern, SNMP sysDescr, etc.); Role groups components by the layer
// of the stack they belong to (web_server, cms, runtime, framework,
// js_library, …) so the UI can display them grouped.
type Fingerprint struct {
	Product      string `json:"product"`
	Version      string `json:"version,omitempty"`
	Edition      string `json:"edition,omitempty"`
	Source       string `json:"source,omitempty"`
	Role         string `json:"role,omitempty"`
	ClusterRole  string `json:"cluster_role,omitempty"`
	ClusterName  string `json:"cluster_name,omitempty"`
	AuthRequired *bool  `json:"auth_required,omitempty"`
	TLSRequired  *bool  `json:"tls_required,omitempty"`
	Anonymous    bool   `json:"anonymous"`
	CapturedAt   string `json:"captured_at"`
}
