package probe

// needsProbeFallback reports whether a registered handler produced only a
// generic tcp label without structured metadata — the usual signal that
// the dedicated probe did not recognise the peer.
func needsProbeFallback(result *Result) bool {
	if result == nil {
		return false
	}

	if result.Protocol != protocolTCP {
		return false
	}

	if result.Fingerprint != nil && result.Fingerprint.Product != "" {
		return false
	}

	if len(result.Components) > 0 {
		return false
	}

	if result.HTTP != nil || result.TLS != nil || result.SSH != nil || result.SMTP != nil {
		return false
	}

	return true
}

// mergeProbeResults keeps the registered handler result but upgrades it when
// the banner/TLS/HTTP fallback found something richer.
func mergeProbeResults(primary, fallback *Result) *Result {
	if primary == nil {
		return fallback
	}

	if fallback == nil {
		return primary
	}

	if fallback.Protocol != protocolTCP && primary.Protocol == protocolTCP {
		return fallback
	}

	merged := *primary

	if fallback.Banner != "" && merged.Banner == "" {
		merged.Banner = fallback.Banner
	}

	if fallback.Protocol != protocolTCP && merged.Protocol == protocolTCP {
		merged.Protocol = fallback.Protocol
	}

	if fallback.Fingerprint != nil {
		merged.Fingerprint = fallback.Fingerprint
	}

	if len(fallback.Components) > 0 {
		merged.Components = fallback.Components
	}

	if fallback.HTTP != nil {
		merged.HTTP = fallback.HTTP
	}

	if fallback.TLS != nil {
		merged.TLS = fallback.TLS
	}

	if fallback.SSH != nil {
		merged.SSH = fallback.SSH
	}

	if fallback.SMTP != nil {
		merged.SMTP = fallback.SMTP
	}

	return &merged
}
