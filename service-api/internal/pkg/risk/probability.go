package risk

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk/decay"
)

// Tunable probability constants used by ComputeServiceProbability. Names are
// grouped by the channel they belong to so a future calibration pass can
// find them through grep + adjust them without hunting through the algorithm.
const (
	// pKEVBase is the per-CVE probability contribution for a CISA KEV entry
	// before the temporal-decay multiplier.
	pKEVBase = 0.85

	// p_auth channel — likelihood the service is compromisable given its
	// observed authentication state.
	pAuthAnonymous    = 0.85
	pAuthDefaultCreds = 0.90
	pAuthMissing      = 0.65
	pAuthUnknown      = 0.30
	pAuthRequired     = 0.05

	// p_crypto channel — TLS/SSH cryptographic-hygiene findings.
	pCryptoExpired      = 0.40
	pCryptoWeakProtocol = 0.30
	pCryptoSSHWeakKex   = 0.25
	pCryptoWeakCipher   = 0.20
	pCryptoExpiresSoon  = 0.10
	pCryptoSelfSigned   = 0.10

	// p_app_hygiene channel — HTTP security headers + tech-stack EOL.
	pHygieneEOL          = 0.30
	pHygieneMissingMajor = 0.05 // HSTS / CSP / X-Frame-Options
	pHygieneMissingMinor = 0.03 // X-Content-Type-Options / Referrer-Policy
	pHygieneServerLeak   = 0.05

	// p_network_position channel — graph centrality.
	pNetworkMaxContribution         = 0.40
	networkCentralityHighCutoff     = 0.66
	networkCentralityModerateCutoff = 0.33

	// CVSS → weight transform: (cvss - cutoff) / range, clamped 0..1.
	cvssWeightCutoff = 4.0
	cvssWeightRange  = 6.0

	// pHostUnionCap clamps the unioned host-level P below 1.0 so the exp
	// mapping never asymptotes.
	pHostUnionCap = 0.99
)

// ChannelCode identifies one independent compromise-probability channel. The
// codes are stable wire identifiers persisted in risk_factors and shown to
// the UI; the wire contract is part of the public API surface.
type ChannelCode string

const (
	// ChannelKEV is "exploit known to be in the wild" (CISA KEV catalog).
	ChannelKEV ChannelCode = "kev"
	// ChannelEPSS is "predicted exploitation in the next 30 days" (FIRST EPSS).
	ChannelEPSS ChannelCode = "epss"
	// ChannelExposure is the protocol-baseline channel keyed on port + family.
	ChannelExposure ChannelCode = "exposure"
	// ChannelAuth is the auth/anonymous-access channel.
	ChannelAuth ChannelCode = "auth"
	// ChannelCrypto is the TLS/SSH cryptographic-hygiene channel.
	ChannelCrypto ChannelCode = "crypto"
	// ChannelAppHygiene is the HTTP-header / tech-stack channel.
	ChannelAppHygiene ChannelCode = "app_hygiene"
	// ChannelNetworkPosition is the graph-centrality / lateral-pivot channel.
	ChannelNetworkPosition ChannelCode = "network_position"
)

// Channel is one channel's contribution within a ProbabilityResult.
type Channel struct {
	Code    ChannelCode
	Label   string
	P       float64
	Sources []string
}

// CVEInput is one CVE matched to a service, with the signals the probability
// model needs. Callers build these from uv_service_cve rows.
type CVEInput struct {
	CVEID      string
	CVSS       float64
	EPSS       float64
	KEVAddedAt time.Time
}

// AuthState describes how the service authenticates.
type AuthState int

const (
	// AuthUnknown means the probe could not determine auth requirements.
	AuthUnknown AuthState = iota
	// AuthRequired means credentials are enforced.
	AuthRequired
	// AuthMissing means the service responded without prompting for creds.
	AuthMissing
	// AuthAnonymous means anonymous access succeeded (worst).
	AuthAnonymous
)

// CryptoInput summarises TLS/SSH cryptographic state. Zero values mean
// "no signal" — the channel collapses to its baseline contribution.
type CryptoInput struct {
	TLSPresent     bool
	TLSExpired     bool
	TLSExpiresSoon bool
	WeakProtocol   bool
	WeakCipher     bool
	SelfSigned     bool
	SSHWeakKex     bool
	LastObservedAt time.Time
}

// AppHygieneInput summarises web-application hygiene signals.
type AppHygieneInput struct {
	HTTPApplicable   bool
	MissingHSTS      bool
	MissingCSP       bool
	MissingXFrame    bool
	MissingXCTOpts   bool
	MissingReferrer  bool
	EOLTechStack     bool
	ServerHeaderLeak bool
}

// ServiceProbabilityInputs is the full set of signals consumed by
// ComputeServiceProbability for a single service.
type ServiceProbabilityInputs struct {
	ServiceID            uint64
	Port                 uint16
	Protocol             string
	CVEs                 []CVEInput
	Auth                 AuthState
	DefaultCredsObserved bool
	Crypto               CryptoInput
	AppHygiene           AppHygieneInput
	NetworkPosition      float64
	LastSeen             time.Time
	Now                  time.Time
}

// ProbabilityResult is the per-service output: the combined P plus the per
// channel breakdown so risk-explain can render "why".
type ProbabilityResult struct {
	P             float64
	Channels      []Channel
	RecencyFactor float64
}

// ComputeServiceProbability returns the per-service compromise probability and
// the channel-by-channel breakdown. The function is deterministic and
// side-effect free.
func ComputeServiceProbability(inputs ServiceProbabilityInputs, priors PriorTable, policy Policy) ProbabilityResult {
	now := inputs.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	channels := make([]Channel, 0, 7)

	pKEV, kevSources := computePKEV(inputs.CVEs, policy, now)
	channels = append(channels, Channel{
		Code:    ChannelKEV,
		Label:   labelForKEV(len(kevSources)),
		P:       pKEV,
		Sources: kevSources,
	})

	pEPSS, epssSources := computePEPSS(inputs.CVEs, policy, now)
	channels = append(channels, Channel{
		Code:    ChannelEPSS,
		Label:   labelForEPSS(len(epssSources)),
		P:       pEPSS,
		Sources: epssSources,
	})

	pExposure, exposureLabel := computePExposure(inputs.Port, inputs.Protocol, priors)
	channels = append(channels, Channel{
		Code:  ChannelExposure,
		Label: exposureLabel,
		P:     pExposure,
	})

	pAuth, authLabel := computePAuth(inputs.Auth, inputs.DefaultCredsObserved)
	channels = append(channels, Channel{
		Code:  ChannelAuth,
		Label: authLabel,
		P:     pAuth,
	})

	pCrypto, cryptoLabel := computePCrypto(inputs.Crypto, policy, now)
	channels = append(channels, Channel{
		Code:  ChannelCrypto,
		Label: cryptoLabel,
		P:     pCrypto,
	})

	pAppHygiene, hygieneLabel := computePAppHygiene(inputs.AppHygiene)
	channels = append(channels, Channel{
		Code:  ChannelAppHygiene,
		Label: hygieneLabel,
		P:     pAppHygiene,
	})

	pNetwork, networkLabel := computePNetworkPosition(inputs.NetworkPosition)
	channels = append(channels, Channel{
		Code:  ChannelNetworkPosition,
		Label: networkLabel,
		P:     pNetwork,
	})

	combined := unionProbabilities(channels)
	recency := decay.HalfLifeDecay(decay.Age(now, inputs.LastSeen), policy.RecencyHalfLife, policy.RecencyFloor)

	final := combined * recency
	if final > pHostUnionCap {
		final = pHostUnionCap
	}

	return ProbabilityResult{
		P:             final,
		Channels:      channels,
		RecencyFactor: recency,
	}
}

// unionProbabilities combines independent channel probabilities via the
// product-complement rule: 1 - Π(1 - p_i). Channel.P values outside
// [0,1] are clamped before the multiplication.
func unionProbabilities(channels []Channel) float64 {
	complement := 1.0

	for _, channel := range channels {
		p := clamp01(channel.P)
		complement *= 1.0 - p
	}

	return 1.0 - complement
}

// weightedCVE pairs a CVE identifier with the per-CVE contribution derived
// for one channel. Top-3 of these unioned with product-complement gives the
// channel's aggregate probability while preserving diminishing returns.
type weightedCVE struct {
	id string
	p  float64
}

func computePKEV(cves []CVEInput, policy Policy, now time.Time) (float64, []string) {
	scored := make([]weightedCVE, 0, len(cves))

	for _, cve := range cves {
		if cve.KEVAddedAt.IsZero() {
			continue
		}

		multiplier := decay.HalfLifeDecay(decay.Age(now, cve.KEVAddedAt), policy.KEVHalfLife, policy.KEVFloor)
		scored = append(scored, weightedCVE{id: cve.CVEID, p: pKEVBase * multiplier})
	}

	return topThreeUnion(scored)
}

func computePEPSS(cves []CVEInput, policy Policy, now time.Time) (float64, []string) {
	scored := make([]weightedCVE, 0, len(cves))

	for _, cve := range cves {
		if cve.EPSS <= 0 {
			continue
		}

		cvssWeight := clamp01((cve.CVSS - cvssWeightCutoff) / cvssWeightRange)
		if cvssWeight <= 0 {
			continue
		}

		anchor := cve.KEVAddedAt
		if anchor.IsZero() {
			anchor = now
		}

		multiplier := decay.HalfLifeDecay(decay.Age(now, anchor), policy.EPSSHalfLife, policy.EPSSFloor)
		scored = append(scored, weightedCVE{id: cve.CVEID, p: cve.EPSS * cvssWeight * multiplier})
	}

	return topThreeUnion(scored)
}

// topThreeUnion takes the three highest-p entries from scored and unions
// them through the product-complement rule. The "top three" cap preserves
// diminishing returns — once an attacker has three credible kill chains
// stacking a fourth barely moves the needle.
func topThreeUnion(scored []weightedCVE) (float64, []string) {
	if len(scored) == 0 {
		return 0, nil
	}

	sort.Slice(scored, func(i, j int) bool { return scored[i].p > scored[j].p })

	limit := 3
	if len(scored) < limit {
		limit = len(scored)
	}

	complement := 1.0
	sources := make([]string, 0, limit)

	for i := range limit {
		complement *= 1.0 - clamp01(scored[i].p)
		sources = append(sources, scored[i].id)
	}

	return 1.0 - complement, sources
}

func computePExposure(port uint16, protocol string, priors PriorTable) (float64, string) {
	bucket := ClassifyPort(port)
	family := ClassifyProtocol(protocol)

	p, _ := priors.PExposure(bucket, family)

	return p, labelForExposure(bucket)
}

func computePAuth(state AuthState, defaultCredsObserved bool) (float64, string) {
	if defaultCredsObserved {
		return pAuthDefaultCreds, "Default credentials observed"
	}

	switch state {
	case AuthAnonymous:
		return pAuthAnonymous, "Anonymous access accepted"
	case AuthMissing:
		return pAuthMissing, "No authentication enforced"
	case AuthRequired:
		return pAuthRequired, "Authentication required"
	default:
		return pAuthUnknown, "Authentication state unknown"
	}
}

func computePCrypto(crypto CryptoInput, policy Policy, now time.Time) (float64, string) {
	if !crypto.TLSPresent && !crypto.SSHWeakKex {
		return 0.0, "No TLS/SSH findings"
	}

	p := 0.0
	parts := make([]string, 0, 4)

	if crypto.TLSExpired {
		p = unionPair(p, pCryptoExpired)

		parts = append(parts, "expired certificate")
	}

	if crypto.WeakProtocol {
		p = unionPair(p, pCryptoWeakProtocol)

		parts = append(parts, "deprecated TLS protocol")
	}

	if crypto.WeakCipher {
		p = unionPair(p, pCryptoWeakCipher)

		parts = append(parts, "weak cipher")
	}

	if crypto.SelfSigned {
		p = unionPair(p, pCryptoSelfSigned)

		parts = append(parts, "self-signed cert")
	}

	if crypto.TLSExpiresSoon {
		p = unionPair(p, pCryptoExpiresSoon)

		parts = append(parts, "cert expiring < 14d")
	}

	if crypto.SSHWeakKex {
		p = unionPair(p, pCryptoSSHWeakKex)

		parts = append(parts, "weak SSH kex")
	}

	multiplier := decay.HalfLifeDecay(decay.Age(now, crypto.LastObservedAt), policy.TLSHalfLife, policy.TLSFloor)

	if len(parts) == 0 {
		return 0.0, "No TLS/SSH findings"
	}

	return p * multiplier, "TLS/SSH: " + strings.Join(parts, ", ")
}

func computePAppHygiene(hygiene AppHygieneInput) (float64, string) {
	if !hygiene.HTTPApplicable {
		return 0.0, "Not an HTTP service"
	}

	p := 0.0
	parts := make([]string, 0, 4)

	if hygiene.EOLTechStack {
		p = unionPair(p, pHygieneEOL)

		parts = append(parts, "end-of-life tech stack")
	}

	if hygiene.MissingHSTS {
		p = unionPair(p, pHygieneMissingMajor)

		parts = append(parts, "no HSTS")
	}

	if hygiene.MissingCSP {
		p = unionPair(p, pHygieneMissingMajor)

		parts = append(parts, "no CSP")
	}

	if hygiene.MissingXFrame {
		p = unionPair(p, pHygieneMissingMajor)

		parts = append(parts, "no X-Frame-Options")
	}

	if hygiene.MissingXCTOpts {
		p = unionPair(p, pHygieneMissingMinor)

		parts = append(parts, "no X-Content-Type-Options")
	}

	if hygiene.MissingReferrer {
		p = unionPair(p, pHygieneMissingMinor)

		parts = append(parts, "no Referrer-Policy")
	}

	if hygiene.ServerHeaderLeak {
		p = unionPair(p, pHygieneServerLeak)

		parts = append(parts, "version exposed in Server header")
	}

	if len(parts) == 0 {
		return 0.0, "Application hygiene clean"
	}

	return p, "HTTP hygiene: " + strings.Join(parts, ", ")
}

func computePNetworkPosition(centrality float64) (float64, string) {
	if centrality <= 0 {
		return 0.0, "No lateral-movement evidence"
	}

	if centrality > 1 {
		centrality = 1
	}

	contribution := pNetworkMaxContribution * centrality

	if centrality >= networkCentralityHighCutoff {
		return contribution, "High graph centrality (likely pivot)"
	}

	if centrality >= networkCentralityModerateCutoff {
		return contribution, "Moderate graph centrality"
	}

	return contribution, "Low graph centrality"
}

// unionPair returns the union of two independent probabilities. Used by
// channel-internal combiners (multi-finding TLS, multi-header HTTP).
func unionPair(a, b float64) float64 {
	return 1.0 - (1.0-clamp01(a))*(1.0-clamp01(b))
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) || v <= 0 {
		return 0
	}

	if v >= 1 {
		return 1
	}

	return v
}

func labelForKEV(n int) string {
	switch n {
	case 0:
		return "No KEV-listed CVEs"
	case 1:
		return "1 KEV-listed CVE"
	default:
		return "Multiple KEV-listed CVEs"
	}
}

func labelForEPSS(n int) string {
	switch n {
	case 0:
		return "No exploit forecast"
	case 1:
		return "1 EPSS-elevated CVE"
	default:
		return "Multiple EPSS-elevated CVEs"
	}
}

func labelForExposure(bucket PortBucket) string {
	switch bucket {
	case PortBucketDatabase:
		return "Database service exposed"
	case PortBucketBrokerCache:
		return "Broker/cache service exposed"
	case PortBucketRemoteDesktop:
		return "Remote-desktop service exposed"
	case PortBucketPlaintext:
		return "Legacy plaintext protocol"
	case PortBucketHTTP:
		return "HTTP webserver"
	case PortBucketHTTPS:
		return "HTTPS webserver"
	default:
		return "Generic TCP/UDP service"
	}
}
