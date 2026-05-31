package host

import (
	"time"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	httpresponserepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpresponse"
	httpsecurityrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpsecurity"
	servicefingerprintrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	smtpinforepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/smtpinfo"
	sshinforepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/sshinfo"
	tlscertificaterepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
)

func hasCVEs(c cvematch.SeverityCounts) bool {
	return c.Critical+c.High+c.Medium+c.Low > 0
}

func cveMatchesToDTO(rows []cvematch.Detail) []hostdto.ServiceCVE {
	out := make([]hostdto.ServiceCVE, 0, len(rows))

	for _, row := range rows {
		entry := hostdto.ServiceCVE{
			ID:        row.CVEID,
			MatchedAt: row.MatchedAt.Format(time.RFC3339),
		}

		if row.Severity.Valid {
			entry.Severity = row.Severity.String
		}

		if row.CVSSScore.Valid {
			score := row.CVSSScore.Float64
			entry.CVSSScore = &score
		}

		if row.Summary.Valid {
			entry.Summary = row.Summary.String
		}

		if row.Confidence > 0 {
			conf := int(row.Confidence)
			entry.Confidence = &conf
		}

		if row.MatchedVersion.Valid {
			entry.MatchedVersion = row.MatchedVersion.String
		}

		out = append(out, entry)
	}

	return out
}

func httpResponseToDTO(response *httpresponserepository.HTTPResponse) *hostdto.HTTPResponse {
	dto := &hostdto.HTTPResponse{
		Headers:    response.Headers,
		CapturedAt: response.CapturedAt.Format(time.RFC3339),
	}

	if response.StatusCode.Valid {
		code := response.StatusCode.Int32
		dto.StatusCode = &code
	}

	if response.ServerHeader.Valid {
		dto.ServerHeader = response.ServerHeader.String
	}

	if response.Title.Valid {
		dto.Title = response.Title.String
	}

	if response.Body.Valid {
		dto.Body = response.Body.String
	}

	dto.SecurityHeaders = extractSecurityHeaders(response.Headers)

	if response.FaviconHash.Valid {
		hash := response.FaviconHash.Int32
		dto.FaviconHash = &hash
	}

	dto.Technologies = response.Technologies

	if response.RedirectURL.Valid {
		dto.RedirectURL = response.RedirectURL.String
	}

	if len(response.RedirectChain) > 0 {
		chain := make([]hostdto.HTTPRedirectStep, 0, len(response.RedirectChain))

		for _, step := range response.RedirectChain {
			chain = append(chain, hostdto.HTTPRedirectStep{
				URL:        step.URL,
				StatusCode: step.StatusCode,
				Location:   step.Location,
			})
		}

		dto.RedirectChain = chain
	}

	if response.RobotsTxt.Valid {
		dto.RobotsTxt = response.RobotsTxt.String
	}

	if response.SecurityTxt.Valid {
		dto.SecurityTxt = response.SecurityTxt.String
	}

	if response.BodySHA256.Valid {
		dto.BodySHA256 = response.BodySHA256.String
	}

	if response.NotFoundHash.Valid {
		dto.NotFoundHash = response.NotFoundHash.String
	}

	if response.AltSvcRaw.Valid {
		dto.AltSvcRaw = response.AltSvcRaw.String
	}

	dto.HTTP3Supported = response.HTTP3Supported

	return dto
}

// httpSecurityToDTO converts the parsed security-headers snapshot into
// its wire DTO. Returns nil for a nil input so callers can pass through.
func httpSecurityToDTO(snapshot *httpsecurityrepository.HTTPSecurity) *hostdto.HTTPSecurityInfo {
	if snapshot == nil {
		return nil
	}

	dto := &hostdto.HTTPSecurityInfo{
		HSTSIncludeSubdomains:    snapshot.HSTSIncludeSubdomains,
		HSTSPreload:              snapshot.HSTSPreload,
		CSPPresent:               snapshot.CSPPresent,
		CSPHasUnsafeInline:       snapshot.CSPHasUnsafeInline,
		CSPHasUnsafeEval:         snapshot.CSPHasUnsafeEval,
		PermissionsPolicyPresent: snapshot.PermissionsPolicyPresent,
		CookieSecureCount:        snapshot.CookieSecureCount,
		CookieHTTPOnlyCount:      snapshot.CookieHTTPOnlyCount,
		CookieSameSiteStrict:     snapshot.CookieSameSiteStrict,
		CookieSameSiteLax:        snapshot.CookieSameSiteLax,
		CookieSameSiteNone:       snapshot.CookieSameSiteNone,
	}

	if snapshot.HSTSMaxAge.Valid {
		v := snapshot.HSTSMaxAge.Int64
		dto.HSTSMaxAge = &v
	}

	if snapshot.XFrameOptions.Valid {
		dto.XFrameOptions = snapshot.XFrameOptions.String
	}

	if snapshot.XContentTypeOptions.Valid {
		dto.XContentTypeOptions = snapshot.XContentTypeOptions.String
	}

	if snapshot.ReferrerPolicy.Valid {
		dto.ReferrerPolicy = snapshot.ReferrerPolicy.String
	}

	if snapshot.CORSAllowOrigin.Valid {
		dto.CORSAllowOrigin = snapshot.CORSAllowOrigin.String
	}

	return dto
}

func tlsCertToDTO(cert *tlscertificaterepository.TLSCertificate) *hostdto.TLSCert {
	dto := &hostdto.TLSCert{}

	if cert.Subject.Valid {
		dto.Subject = cert.Subject.String
	}

	if cert.Issuer.Valid {
		dto.Issuer = cert.Issuer.String
	}

	if cert.FingerprintSHA256.Valid {
		dto.FingerprintSHA256 = cert.FingerprintSHA256.String
	}

	if cert.NotBefore.Valid {
		dto.NotBefore = cert.NotBefore.Time.Format(time.RFC3339)
	}

	if cert.NotAfter.Valid {
		dto.NotAfter = cert.NotAfter.Time.Format(time.RFC3339)

		days := int(time.Until(cert.NotAfter.Time).Hours() / 24)
		dto.DaysUntilExpiry = &days
	}

	dto.SANs = cert.SANs

	if cert.JARMFingerprint.Valid {
		dto.JARMFingerprint = cert.JARMFingerprint.String
	}

	if cert.TLSVersion.Valid {
		dto.TLSVersion = cert.TLSVersion.String
	}

	if cert.CipherSuite.Valid {
		dto.CipherSuite = cert.CipherSuite.String
	}

	if cert.JA3SHash.Valid {
		dto.JA3SHash = cert.JA3SHash.String
	}

	if cert.JA4SHash.Valid {
		dto.JA4SHash = cert.JA4SHash.String
	}

	if cert.SecurityGrade.Valid {
		dto.SecurityGrade = cert.SecurityGrade.String
	}

	return dto
}

// tlsFindingsToDTO converts the persisted finding rows into their wire
// form. Returns nil for an empty input so omitempty kicks in.
func tlsFindingsToDTO(findings []tlscertificaterepository.TLSFinding) []hostdto.TLSFinding {
	if len(findings) == 0 {
		return nil
	}

	out := make([]hostdto.TLSFinding, 0, len(findings))

	for _, f := range findings {
		entry := hostdto.TLSFinding{
			Severity: f.Severity,
			Code:     f.Code,
		}

		if f.Detail.Valid {
			entry.Detail = f.Detail.String
		}

		out = append(out, entry)
	}

	return out
}

func tlsChainToDTO(nodes []tlscertificaterepository.TLSChainNode) []hostdto.TLSChainEntry {
	if len(nodes) == 0 {
		return nil
	}

	out := make([]hostdto.TLSChainEntry, 0, len(nodes))

	for _, node := range nodes {
		entry := hostdto.TLSChainEntry{Position: node.ChainPosition, SANs: node.SANs}

		if node.Subject.Valid {
			entry.Subject = node.Subject.String
		}

		if node.Issuer.Valid {
			entry.Issuer = node.Issuer.String
		}

		if node.FingerprintSHA256.Valid {
			entry.FingerprintSHA256 = node.FingerprintSHA256.String
		}

		if node.NotBefore.Valid {
			entry.NotBefore = node.NotBefore.Time.Format(time.RFC3339)
		}

		if node.NotAfter.Valid {
			entry.NotAfter = node.NotAfter.Time.Format(time.RFC3339)
		}

		out = append(out, entry)
	}

	return out
}

func serviceFingerprintToDTO(fp *servicefingerprintrepository.Fingerprint) *hostdto.Fingerprint {
	dto := &hostdto.Fingerprint{
		Product:    fp.Product,
		Source:     fp.Source,
		Anonymous:  fp.Anonymous,
		CapturedAt: fp.CapturedAt.Format(time.RFC3339),
	}

	if fp.Version.Valid {
		dto.Version = fp.Version.String
	}

	if fp.Edition.Valid {
		dto.Edition = fp.Edition.String
	}

	if fp.Role.Valid {
		dto.Role = fp.Role.String
	}

	if fp.ClusterRole.Valid {
		dto.ClusterRole = fp.ClusterRole.String
	}

	if fp.ClusterName.Valid {
		dto.ClusterName = fp.ClusterName.String
	}

	if fp.AuthRequired.Valid {
		authRequired := fp.AuthRequired.Bool
		dto.AuthRequired = &authRequired
	}

	if fp.TLSRequired.Valid {
		tlsRequired := fp.TLSRequired.Bool
		dto.TLSRequired = &tlsRequired
	}

	return dto
}

// serviceFingerprintsToDTO renders the full multi-component fingerprint
// stack for a service. Used to populate Service.Fingerprints; the legacy
// scalar Service.Fingerprint stays in place for clients that haven't
// migrated to the array yet.
func serviceFingerprintsToDTO(components []*servicefingerprintrepository.Fingerprint) []hostdto.Fingerprint {
	if len(components) == 0 {
		return nil
	}

	out := make([]hostdto.Fingerprint, 0, len(components))

	for _, comp := range components {
		if comp == nil {
			continue
		}

		out = append(out, *serviceFingerprintToDTO(comp))
	}

	return out
}

// primaryFingerprint picks the component most likely to be useful as a
// single-product display in legacy clients. Preference order: web_server →
// database → cms → runtime → framework → first available. Within a tier
// the row with a non-empty version wins.
func primaryFingerprint(components []*servicefingerprintrepository.Fingerprint) *servicefingerprintrepository.Fingerprint {
	if len(components) == 0 {
		return nil
	}

	priority := map[string]int{
		"web_server": 1,
		"database":   2,
		"cms":        3,
		"runtime":    4,
		"framework":  5,
	}

	bestIdx := 0
	bestPriority := 999

	for i, comp := range components {
		role := ""
		if comp.Role.Valid {
			role = comp.Role.String
		}

		score, ok := priority[role]
		if !ok {
			score = 100
		}

		if !comp.Version.Valid || comp.Version.String == "" {
			score += 10
		}

		if score < bestPriority {
			bestPriority = score
			bestIdx = i
		}
	}

	return components[bestIdx]
}

func sshInfoToDTO(info *sshinforepository.SSHInfo) *hostdto.SSHInfo {
	dto := &hostdto.SSHInfo{
		KexAlgorithms:     info.KexAlgorithms,
		HostKeyAlgorithms: info.HostKeyAlgorithms,
	}

	if info.ServerVersion.Valid {
		dto.ServerVersion = info.ServerVersion.String
	}

	if info.HostKeyType.Valid {
		dto.HostKeyType = info.HostKeyType.String
	}

	if info.HostKeyFingerprint.Valid {
		dto.HostKeyFingerprint = info.HostKeyFingerprint.String
	}

	return dto
}

func smtpInfoToDTO(info *smtpinforepository.SMTPInfo) *hostdto.SMTPInfo {
	dto := &hostdto.SMTPInfo{
		Capabilities: info.Capabilities,
		STARTTLS:     info.STARTTLS,
		AuthMethods:  info.AuthMethods,
	}

	if info.Banner.Valid {
		dto.Banner = info.Banner.String
	}

	if info.MaxMessageSize.Valid {
		size := info.MaxMessageSize.Int64
		dto.MaxMessageSize = &size
	}

	return dto
}

func extractSecurityHeaders(headers map[string]string) *hostdto.SecurityHeaders {
	out := hostdto.SecurityHeaders{
		HSTS:          headers["Strict-Transport-Security"],
		CSP:           headers["Content-Security-Policy"],
		XFrameOptions: headers["X-Frame-Options"],
		XContentType:  headers["X-Content-Type-Options"],
	}

	if out == (hostdto.SecurityHeaders{}) {
		return nil
	}

	return &out
}
