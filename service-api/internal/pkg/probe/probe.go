// Package probe gathers protocol-level metadata from open TCP services.
//
// Architecture: per-protocol files register themselves via Register() in
// init() so the dispatcher in stack.go stays trivial. The Stack type
// composes the registered handlers and exposes the Prober interface.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"time"
)

// Protocol labels carried in Result.Protocol for transports without their
// own fingerprint.
const (
	protocolHTTP   = "http"
	protocolHTTPS  = "https"
	protocolTCP    = "tcp"
	protocolBanner = "banner"
)

// Transport identifies the L4 transport used for a probe target.
type Transport string

const (
	// TransportTCP is the default — TCP connect + protocol handshake.
	TransportTCP Transport = "TCP"
	// TransportUDP is UDP request/response style probing.
	TransportUDP Transport = "UDP"
)

// Target is the (IP, port) pair to probe.
type Target struct {
	IP        netip.Addr
	Port      uint16
	Transport Transport
}

// HTTPResult is what an HTTP probe returns when successful.
type HTTPResult struct {
	StatusCode    int
	Server        string
	Title         string
	Headers       map[string]string
	Body          string
	RedirectURL   string
	RedirectChain []RedirectStep
	FaviconHash   *int32
	Technologies  []string
	RobotsTxt     string
	SecurityTxt   string
	// AltSvcRaw is the verbatim Alt-Svc response header advertising
	// alternative endpoints (RFC 7838). Empty when not present.
	AltSvcRaw string
	// HTTP3Supported is true when AltSvcRaw advertises an h3 or h3-XX endpoint.
	HTTP3Supported bool
	// BodySHA256 is the hex-encoded SHA-256 of the response body bytes.
	// Useful for grouping default install pages whose content is identical
	// across deployments.
	BodySHA256 string
	// NotFoundHash is the hex-encoded SHA-256 of the body served for a
	// random non-existent path. Default 404 pages often expose framework
	// fingerprints even when the Server header is hidden.
	NotFoundHash string
	// Security parses common HTTP security response headers from Headers
	// into a structured form for filtering and grading.
	Security *HTTPSecurity
}

// HTTPSecurity captures parsed values of well-known HTTP security
// response headers. All fields are zero-valued when the header was
// missing or unparseable.
type HTTPSecurity struct {
	HSTSMaxAge               int64
	HSTSIncludeSubdomains    bool
	HSTSPreload              bool
	CSPPresent               bool
	CSPHasUnsafeInline       bool
	CSPHasUnsafeEval         bool
	XFrameOptions            string
	XContentTypeOptions      string
	ReferrerPolicy           string
	PermissionsPolicyPresent bool
	CORSAllowOrigin          string
	CookieSecureCount        int
	CookieHTTPOnlyCount      int
	CookieSameSiteStrict     int
	CookieSameSiteLax        int
	CookieSameSiteNone       int
}

// RedirectStep records a single hop in an HTTP redirect chain.
type RedirectStep struct {
	URL        string
	StatusCode int
	Location   string
}

// SMTPResult holds SMTP capability metadata captured during the probe.
type SMTPResult struct {
	Banner         string
	Capabilities   []string
	STARTTLS       bool
	AuthMethods    []string
	MaxMessageSize int64
}

// TLSResult is what a TLS handshake produces when successful.
type TLSResult struct {
	Subject           string
	Issuer            string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
	RawPEM            string
	SANs              []string
	JARMFingerprint   string
	TLSVersion        string
	CipherSuite       string
	// Chain holds intermediate + root certificates beyond the leaf, ordered
	// from the certificate that signed the leaf upward to the trust anchor.
	Chain []TLSCertificate
	// JA3SHash and JA4SHash are server-side TLS fingerprints derived from
	// ServerHello selections.
	JA3SHash string
	JA4SHash string
	// NegotiatedProtocol is the ALPN value selected during the handshake
	// (e.g. "h2", "http/1.1", "h3"). Empty when no ALPN was offered.
	NegotiatedProtocol string
	// Findings is the list of security issues detected on the certificate
	// or handshake (weak protocol, expired cert, hostname mismatch, …).
	Findings []TLSFinding
	// SecurityGrade is the derived letter grade summarising Findings.
	// Empty when grading was not performed.
	SecurityGrade string
}

// TLSFinding is one detected security issue against a TLS handshake.
type TLSFinding struct {
	// Severity is one of info, low, medium, high, critical.
	Severity string
	// Code is a stable machine identifier (e.g. weak_protocol, expired).
	Code string
	// Detail is a short human-readable explanation.
	Detail string
}

// TLSCertificate is one node in the certificate chain stored alongside a
// TLSResult.
type TLSCertificate struct {
	Subject           string
	Issuer            string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
	RawPEM            string
	SANs              []string
}

// FingerprintResult holds product-level metadata captured for a recognised
// service.
type FingerprintResult struct {
	Product      string
	Version      string
	Edition      string
	ClusterRole  string
	ClusterName  string
	AuthRequired *bool
	TLSRequired  *bool
	Anonymous    bool
	RawJSON      []byte
}

// Component source labels: where the (product, version) pair was extracted
// from. Used by ingest to populate uv_service_fingerprint.source and by the
// UI to explain how a CVE was attributed.
const (
	ComponentSourceHTTPServer    = "http_server_header"
	ComponentSourcePoweredBy     = "x_powered_by"
	ComponentSourceMetaGenerator = "meta_generator"
	ComponentSourceBodyPattern   = "body_pattern"
	ComponentSourceCookie        = "cookie"
	ComponentSourceFavicon       = "favicon"
	ComponentSourceSNMP          = "snmp_sysdescr"
	ComponentSourceSSHBanner     = "ssh_banner"
	ComponentSourceSMTPBanner    = "smtp_banner"
	ComponentSourceTLSSubject    = "tls_subject"
	ComponentSourceBannerGeneric = "banner_generic"
	ComponentSourceProtocolProbe = "protocol_probe"
)

// Component role labels: which layer of the technology stack a component
// belongs to. The frontend uses this to group fingerprints in service cards.
const (
	ComponentRoleWebServer = "web_server"
	ComponentRoleCMS       = "cms"
	ComponentRoleRuntime   = "runtime"
	ComponentRoleFramework = "framework"
	ComponentRoleDatabase  = "database"
	ComponentRoleJSLibrary = "js_library"
	ComponentRoleOS        = "os"
	ComponentRoleDevice    = "device"
	ComponentRoleOther     = "other"
)

// TechComponent describes one technology layer detected on a service. A
// single HTTP service can yield several components: nginx (web_server) plus
// WordPress (cms) plus PHP (runtime) plus jQuery (js_library), each with
// its own version and CVE surface.
type TechComponent struct {
	Product      string
	Version      string
	Edition      string
	Source       string
	Role         string
	ClusterRole  string
	ClusterName  string
	AuthRequired *bool
	TLSRequired  *bool
	Anonymous    bool
	RawJSON      []byte
}

// SSHResult holds SSH-specific metadata captured during the probe.
type SSHResult struct {
	ServerVersion      string
	HostKeyType        string
	HostKeyFingerprint string
	KexAlgorithms      []string
	HostKeyAlgorithms  []string
}

// GRPCResult holds gRPC-specific metadata captured during the probe.
type GRPCResult struct {
	// Detected is true when the peer behaves like a gRPC server.
	Detected bool
	// Reflection is true when the server reflection API responded with a
	// non-UNIMPLEMENTED status, indicating reflection is enabled.
	Reflection bool
}

// GraphQLResult holds GraphQL endpoint metadata captured during the probe.
type GraphQLResult struct {
	// Endpoint is the URL path (e.g. "/graphql") that served the response.
	Endpoint string
	// IntrospectionEnabled is true when a __schema introspection query
	// returned a parseable response.
	IntrospectionEnabled bool
	// QueryTypeName is the root query type name returned by introspection
	// (typically "Query"). Empty when introspection is blocked.
	QueryTypeName string
}

// Result aggregates everything a probe set produced for a single target.
//
// Components carries the full multi-layer technology stack; Fingerprint is
// kept as the "primary" component (highest-signal layer) so callers that
// only need a single product/version pair stay unchanged.
type Result struct {
	Target      Target
	Protocol    string
	Banner      string
	HTTP        *HTTPResult
	TLS         *TLSResult
	SSH         *SSHResult
	SMTP        *SMTPResult
	GRPC        *GRPCResult
	GraphQL     *GraphQLResult
	Fingerprint *FingerprintResult
	Components  []TechComponent
}

// BannerHash returns the hex-encoded SHA-256 of the banner string, or empty.
func (r *Result) BannerHash() string {
	if r.Banner == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(r.Banner))

	return hex.EncodeToString(sum[:])
}

// Prober runs the protocol probes appropriate for the given target.
type Prober interface {
	Probe(ctx context.Context, target Target) (*Result, error)
}
