// Package signals batches the per-service inputs the risk scorer consumes
// (CVE list, TLS / SSH crypto state, HTTP header hygiene, fingerprint auth
// state) into one shape so the host aggregator can iterate without issuing
// N+1 queries.
package signals

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpresponse"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpsecurity"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/sshinfo"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
)

// expiresSoonWindow defines "certificate is about to expire" — used by the
// crypto channel's TLSExpiresSoon flag.
const expiresSoonWindow = 14 * 24 * time.Hour

// ServiceSignals is the per-service signal bundle ready for the scorer.
type ServiceSignals struct {
	CVEs                 []risk.CVEInput
	Auth                 risk.AuthState
	DefaultCredsObserved bool
	Crypto               risk.CryptoInput
	AppHygiene           risk.AppHygieneInput
	Observed             risk.SignalsObserved
}

// Collector is the host-level batch loader that resolves ServiceSignals for
// every service on a host in a constant number of queries.
type Collector struct {
	httpResponseRepository       httpresponse.Repository
	httpSecurityRepository       httpsecurity.Repository
	tlsCertificateRepository     tlscertificate.Repository
	sshInfoRepository            sshinfo.Repository
	serviceFingerprintRepository servicefingerprint.Repository
	cveMatchRepository           cvematch.Repository
}

// New builds a Collector. Constructor parameters use full names per the
// repository-naming rule.
func New(
	httpResponseRepository httpresponse.Repository,
	httpSecurityRepository httpsecurity.Repository,
	tlsCertificateRepository tlscertificate.Repository,
	sshInfoRepository sshinfo.Repository,
	serviceFingerprintRepository servicefingerprint.Repository,
	cveMatchRepository cvematch.Repository,
) *Collector {
	return &Collector{
		httpResponseRepository:       httpResponseRepository,
		httpSecurityRepository:       httpSecurityRepository,
		tlsCertificateRepository:     tlsCertificateRepository,
		sshInfoRepository:            sshInfoRepository,
		serviceFingerprintRepository: serviceFingerprintRepository,
		cveMatchRepository:           cveMatchRepository,
	}
}

// Collect resolves ServiceSignals for the supplied service IDs in one batch
// per repository. Missing rows collapse to zero-value signals (which the
// scorer treats as "no evidence"), so the result map always contains an entry
// for every requested ID.
//
// bannerPresent is the host aggregator's per-service "did we observe a
// banner?" hint, kept here so the completeness meter does not lie about the
// raw banner column when its absence is the only signal we have for that
// service.
func (c *Collector) Collect(ctx context.Context, serviceIDs []uint64, bannerPresent map[uint64]bool) (map[uint64]ServiceSignals, error) {
	out := make(map[uint64]ServiceSignals, len(serviceIDs))

	if len(serviceIDs) == 0 {
		return out, nil
	}

	for _, id := range serviceIDs {
		out[id] = ServiceSignals{Auth: risk.AuthUnknown}
	}

	var (
		cveByService          map[uint64][]cvematch.Detail
		tlsByService          map[uint64]*tlscertificate.TLSCertificate
		tlsFindingsByService  map[uint64][]tlscertificate.TLSFinding
		sshByService          map[uint64]*sshinfo.SSHInfo
		httpByService         map[uint64]*httpresponse.HTTPResponse
		securityByService     map[uint64]*httpsecurity.HTTPSecurity
		fingerprintsByService map[uint64][]*servicefingerprint.Fingerprint
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		v, err := c.cveMatchRepository.ListByServiceIDs(gctx, serviceIDs)
		cveByService = v

		return err
	})
	g.Go(func() error {
		v, err := c.tlsCertificateRepository.GetByServiceIDs(gctx, serviceIDs)
		tlsByService = v

		return err
	})
	g.Go(func() error {
		v, err := c.tlsCertificateRepository.GetFindingsByServiceIDs(gctx, serviceIDs)
		tlsFindingsByService = v

		return err
	})
	g.Go(func() error {
		v, err := c.sshInfoRepository.GetByServiceIDs(gctx, serviceIDs)
		sshByService = v

		return err
	})
	g.Go(func() error {
		v, err := c.httpResponseRepository.GetByServiceIDs(gctx, serviceIDs)
		httpByService = v

		return err
	})
	g.Go(func() error {
		v, err := c.httpSecurityRepository.GetByServiceIDs(gctx, serviceIDs)
		securityByService = v

		return err
	})
	g.Go(func() error {
		v, err := c.serviceFingerprintRepository.GetByServiceIDs(gctx, serviceIDs)
		fingerprintsByService = v

		return err
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	for _, id := range serviceIDs {
		signals := out[id]
		signals.CVEs = cveInputs(cveByService[id])
		signals.Crypto = cryptoInput(tlsByService[id], tlsFindingsByService[id], sshByService[id], now)
		signals.AppHygiene = appHygieneInput(httpByService[id], securityByService[id])
		signals.Auth, signals.DefaultCredsObserved = authState(fingerprintsByService[id])
		signals.Observed = risk.SignalsObserved{
			HasBanner:      bannerPresent[id],
			HasTLS:         tlsByService[id] != nil,
			HasHTTPHeaders: securityByService[id] != nil,
			HasFingerprint: len(fingerprintsByService[id]) > 0,
			HasCVEMatch:    len(cveByService[id]) > 0,
			HasFavicon:     httpByService[id] != nil && httpByService[id].FaviconHash.Valid,
		}

		out[id] = signals
	}

	return out, nil
}

func cveInputs(details []cvematch.Detail) []risk.CVEInput {
	if len(details) == 0 {
		return nil
	}

	out := make([]risk.CVEInput, 0, len(details))

	for _, detail := range details {
		input := risk.CVEInput{CVEID: detail.CVEID}
		if detail.CVSSScore.Valid {
			input.CVSS = detail.CVSSScore.Float64
		}

		if detail.EPSSScore.Valid {
			input.EPSS = detail.EPSSScore.Float64
		}

		if detail.KEVAddedAt.Valid {
			input.KEVAddedAt = detail.KEVAddedAt.Time
		}

		out = append(out, input)
	}

	return out
}

func cryptoInput(
	cert *tlscertificate.TLSCertificate,
	findings []tlscertificate.TLSFinding,
	ssh *sshinfo.SSHInfo,
	now time.Time,
) risk.CryptoInput {
	input := risk.CryptoInput{}

	if cert != nil {
		input.TLSPresent = true
		input.LastObservedAt = now

		if cert.NotAfter.Valid {
			if now.After(cert.NotAfter.Time) {
				input.TLSExpired = true
			} else if cert.NotAfter.Time.Sub(now) <= expiresSoonWindow {
				input.TLSExpiresSoon = true
			}
		}

		if cert.Subject.Valid && cert.Issuer.Valid && cert.Subject.String == cert.Issuer.String {
			input.SelfSigned = true
		}

		if cert.TLSVersion.Valid && isWeakTLSProtocol(cert.TLSVersion.String) {
			input.WeakProtocol = true
		}

		if cert.CipherSuite.Valid && isWeakCipher(cert.CipherSuite.String) {
			input.WeakCipher = true
		}
	}

	for _, finding := range findings {
		switch strings.ToLower(finding.Code) {
		case "weak_protocol", "deprecated_protocol", "weak_tls_protocol":
			input.WeakProtocol = true
		case "weak_cipher":
			input.WeakCipher = true
		case "expired", "expired_cert":
			input.TLSExpired = true
		case "self_signed":
			input.SelfSigned = true
		}
	}

	if ssh != nil {
		for _, kex := range ssh.KexAlgorithms {
			if isWeakSSHKex(kex) {
				input.SSHWeakKex = true

				if input.LastObservedAt.IsZero() {
					input.LastObservedAt = ssh.CapturedAt
				}

				break
			}
		}
	}

	return input
}

func appHygieneInput(response *httpresponse.HTTPResponse, security *httpsecurity.HTTPSecurity) risk.AppHygieneInput {
	if response == nil && security == nil {
		return risk.AppHygieneInput{}
	}

	input := risk.AppHygieneInput{HTTPApplicable: true}

	if security == nil {
		input.MissingHSTS = true
		input.MissingCSP = true
		input.MissingXFrame = true
		input.MissingXCTOpts = true
		input.MissingReferrer = true
	} else {
		input.MissingHSTS = !security.HSTSMaxAge.Valid || security.HSTSMaxAge.Int64 <= 0
		input.MissingCSP = !security.CSPPresent
		input.MissingXFrame = !security.XFrameOptions.Valid || security.XFrameOptions.String == ""
		input.MissingXCTOpts = !security.XContentTypeOptions.Valid || security.XContentTypeOptions.String == ""
		input.MissingReferrer = !security.ReferrerPolicy.Valid || security.ReferrerPolicy.String == ""
	}

	if response != nil {
		input.ServerHeaderLeak = response.ServerHeader.Valid && exposesVersion(response.ServerHeader.String)
		input.EOLTechStack = anyEOLTechnology(response.Technologies)
	}

	return input
}

func authState(fingerprints []*servicefingerprint.Fingerprint) (risk.AuthState, bool) {
	state := risk.AuthUnknown
	defaultCreds := false

	for _, fp := range fingerprints {
		if fp == nil {
			continue
		}

		if fp.Anonymous {
			state = risk.AuthAnonymous
		}

		if fp.AuthRequired.Valid {
			if fp.AuthRequired.Bool && state != risk.AuthAnonymous && state != risk.AuthMissing {
				state = risk.AuthRequired
			} else if !fp.AuthRequired.Bool && state != risk.AuthAnonymous {
				state = risk.AuthMissing
			}
		}

		if hasDefaultCredsRole(fp.Role) {
			defaultCreds = true
		}
	}

	return state, defaultCreds
}

func hasDefaultCredsRole(role sql.NullString) bool {
	if !role.Valid {
		return false
	}

	return strings.Contains(strings.ToLower(role.String), "default_credentials")
}

func isWeakTLSProtocol(version string) bool {
	v := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(version), " ", ""))

	return v == "SSLV2" || v == "SSLV3" || v == "TLSV1" || v == "TLSV1.0" || v == "TLS1.0" || v == "TLSV1.1" || v == "TLS1.1"
}

func isWeakCipher(suite string) bool {
	s := strings.ToUpper(strings.TrimSpace(suite))

	for _, marker := range []string{"_RC4_", "_DES_", "_3DES_", "_NULL_", "_EXPORT", "_MD5", "_ANON"} {
		if strings.Contains(s, marker) {
			return true
		}
	}

	return false
}

func isWeakSSHKex(kex string) bool {
	k := strings.ToLower(strings.TrimSpace(kex))

	return strings.HasPrefix(k, "diffie-hellman-group1-") ||
		strings.HasPrefix(k, "diffie-hellman-group14-sha1") ||
		strings.HasPrefix(k, "diffie-hellman-group-exchange-sha1") ||
		strings.Contains(k, "-sha1")
}

func exposesVersion(serverHeader string) bool {
	s := strings.TrimSpace(serverHeader)
	if s == "" {
		return false
	}

	return strings.ContainsAny(s, "0123456789")
}

func anyEOLTechnology(technologies []string) bool {
	for _, tech := range technologies {
		if isEOLTechnology(tech) {
			return true
		}
	}

	return false
}

func isEOLTechnology(name string) bool {
	t := strings.ToLower(strings.TrimSpace(name))

	for _, marker := range []string{
		"php/5", "php/4", "php 5", "php 4",
		"python/2", "python 2",
		"jquery/1.", "jquery/2.",
		"openssl/0", "openssl/1.0",
		"apache/1.", "apache/2.0", "apache/2.2",
		"nginx/0.", "nginx/1.0", "nginx/1.2", "nginx/1.4",
		"iis/5", "iis/6", "iis/7",
		"wordpress/3.", "wordpress/4.",
		"drupal/6", "drupal/7",
		"struts/1.", "struts/2.0", "struts/2.3",
		"java/1.6", "java/1.7",
		"node.js/0", "node.js/4", "node.js/6", "node.js/8", "node.js/10",
	} {
		if strings.Contains(t, marker) {
			return true
		}
	}

	return false
}
