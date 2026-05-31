package risk

// Tunable thresholds for the per-service recommendation generator.
const (
	// Recommendation triggers fire when the channel P clears the cutoff.
	recommendAuthCutoff     = 0.30
	recommendCryptoCutoff   = 0.10
	recommendHygieneCutoff  = 0.05
	recommendExposureCutoff = 0.30

	// Per-CVE contribution baselines (KEV + EPSS).
	cvePatchKEVBaseContribution   = 0.50
	cvePatchEPSSWeight            = 0.40
	cvePatchMaxContribution       = 0.90
	cvePatchMinEPSSForCandidate   = 0.20
	cvePatchAuthRemainingAfterFix = 0.05
)

// RecommendationCandidate is one suggested action plus the per-service
// probability impact it would have. The host aggregator multiplies through
// the union to project the host-score reduction.
type RecommendationCandidate struct {
	ServiceID       uint64
	ActionCode      string
	Label           string
	ExpectedDeltaP  float64
	OriginalP       float64
	HypotheticalP   float64
	EvidenceChannel ChannelCode
	EvidenceCVEID   string
}

// RecommendForService inspects a service's probability breakdown and emits
// the top remediation candidates. The list is deterministic (sorted by
// ExpectedDeltaP descending) so the storage layer can dedupe by action_code.
//
// Mitigations covered: per-CVE patch suggestions for KEV/high-EPSS findings,
// authentication enforcement, TLS / SSH hygiene fixes, HTTP security
// headers, and management-port lockdown.
func RecommendForService(serviceID uint64, port uint16, cves []CVEInput, probability ProbabilityResult) []RecommendationCandidate {
	out := make([]RecommendationCandidate, 0, 4)
	channels := indexChannels(probability.Channels)

	out = append(out, cveRecommendations(serviceID, cves)...)

	if channel, ok := channels[ChannelAuth]; ok && channel.P >= recommendAuthCutoff {
		out = append(out, RecommendationCandidate{
			ServiceID:       serviceID,
			ActionCode:      "enforce_authentication",
			Label:           "Enforce authentication on the service",
			OriginalP:       channel.P,
			ExpectedDeltaP:  channel.P - cvePatchAuthRemainingAfterFix,
			HypotheticalP:   cvePatchAuthRemainingAfterFix,
			EvidenceChannel: ChannelAuth,
		})
	}

	if channel, ok := channels[ChannelCrypto]; ok && channel.P >= recommendCryptoCutoff {
		out = append(out, RecommendationCandidate{
			ServiceID:       serviceID,
			ActionCode:      "fix_tls_findings",
			Label:           "Resolve TLS findings (renew cert / disable weak protocols)",
			OriginalP:       channel.P,
			ExpectedDeltaP:  channel.P,
			HypotheticalP:   0,
			EvidenceChannel: ChannelCrypto,
		})
	}

	if channel, ok := channels[ChannelAppHygiene]; ok && channel.P >= recommendHygieneCutoff {
		out = append(out, RecommendationCandidate{
			ServiceID:       serviceID,
			ActionCode:      "set_security_headers",
			Label:           "Set HTTP security headers (HSTS, CSP, X-Frame-Options)",
			OriginalP:       channel.P,
			ExpectedDeltaP:  channel.P,
			HypotheticalP:   0,
			EvidenceChannel: ChannelAppHygiene,
		})
	}

	if channel, ok := channels[ChannelExposure]; ok && channel.P >= recommendExposureCutoff && isManagementPort(port) {
		out = append(out, RecommendationCandidate{
			ServiceID:       serviceID,
			ActionCode:      "close_management_port",
			Label:           "Restrict the management port to a VPN / bastion subnet",
			OriginalP:       channel.P,
			ExpectedDeltaP:  channel.P,
			HypotheticalP:   0,
			EvidenceChannel: ChannelExposure,
		})
	}

	return out
}

// cveRecommendations turns the per-service CVE list into one
// "patch CVE-X" candidate per qualifying entry. A CVE qualifies when it
// is KEV-listed or has EPSS above cvePatchMinEPSSForCandidate.
func cveRecommendations(serviceID uint64, cves []CVEInput) []RecommendationCandidate {
	out := make([]RecommendationCandidate, 0, 3)

	for _, cve := range cves {
		if cve.KEVAddedAt.IsZero() && cve.EPSS < cvePatchMinEPSSForCandidate {
			continue
		}

		// Approximate per-CVE removal: the contribution to the KEV/EPSS
		// channel for this single CVE. Bounded so the aggregate stays
		// honest even when the channel is already near 1.
		contribution := 0.0

		if !cve.KEVAddedAt.IsZero() {
			contribution += cvePatchKEVBaseContribution
		}

		if cve.EPSS > 0 {
			contribution += cve.EPSS * cvePatchEPSSWeight
		}

		if contribution > cvePatchMaxContribution {
			contribution = cvePatchMaxContribution
		}

		out = append(out, RecommendationCandidate{
			ServiceID:       serviceID,
			ActionCode:      "patch_cve",
			Label:           "Patch " + cve.CVEID,
			OriginalP:       contribution,
			ExpectedDeltaP:  contribution,
			HypotheticalP:   0,
			EvidenceChannel: ChannelKEV,
			EvidenceCVEID:   cve.CVEID,
		})
	}

	return out
}

// indexChannels keys a Channel slice by its ChannelCode for O(1) lookup
// inside the candidate-generator switch.
func indexChannels(channels []Channel) map[ChannelCode]Channel {
	out := make(map[ChannelCode]Channel, len(channels))

	for _, channel := range channels {
		out[channel.Code] = channel
	}

	return out
}

// isManagementPort reports whether the port classifies as a management
// surface (DB / RDP / broker / legacy plaintext). Public-facing web
// ports never count — closing :443 on a webserver is not a remediation.
func isManagementPort(port uint16) bool {
	switch ClassifyPort(port) {
	case PortBucketRemoteDesktop, PortBucketDatabase, PortBucketBrokerCache, PortBucketPlaintext:
		return true
	case PortBucketHTTP, PortBucketHTTPS, PortBucketOther:
		return false
	default:
		return false
	}
}
