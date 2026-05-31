package host

import (
	"time"

	httpresponserepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpresponse"
	servicefingerprintrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	sshinforepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/sshinfo"
	tlscertificaterepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
)

var weakCipherSuites = map[string]bool{
	"TLS_RSA_WITH_RC4_128_SHA":          true,
	"TLS_RSA_WITH_RC4_128_MD5":          true,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":     true,
	"TLS_RSA_WITH_NULL_MD5":             true,
	"TLS_RSA_WITH_NULL_SHA":             true,
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":    true,
	"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA": true,
	"TLS_RSA_WITH_DES_CBC_SHA":          true,
}

var weakKexAlgorithms = map[string]bool{
	"diffie-hellman-group1-sha1":  true,
	"diffie-hellman-group14-sha1": true,
}

func enrichRiskScore(
	base int32,
	baseFactors []string,
	tls *tlscertificaterepository.TLSCertificate,
	http *httpresponserepository.HTTPResponse,
	ssh *sshinforepository.SSHInfo,
	fp *servicefingerprintrepository.Fingerprint,
) (int, []string) {
	score := int(base)

	factors := make([]string, len(baseFactors))
	copy(factors, baseFactors)

	if tls != nil && tls.NotAfter.Valid {
		now := time.Now()

		switch {
		case tls.NotAfter.Time.Before(now):
			score += 30

			factors = append(factors, "expired_tls_cert")
		case tls.NotAfter.Time.Before(now.Add(30 * 24 * time.Hour)):
			score += 15

			factors = append(factors, "expiring_tls_cert")
		}

		if tls.CipherSuite.Valid && weakCipherSuites[tls.CipherSuite.String] {
			score += 20

			factors = append(factors, "weak_cipher_suite")
		}
	}

	if http != nil && tls != nil && http.Headers["Strict-Transport-Security"] == "" {
		score += 10

		factors = append(factors, "missing_hsts")
	}

	if ssh != nil {
		for _, alg := range ssh.KexAlgorithms {
			if weakKexAlgorithms[alg] {
				score += 15

				factors = append(factors, "weak_kex_algorithm")

				break
			}
		}
	}

	if fp != nil && fp.AuthRequired.Valid && !fp.AuthRequired.Bool {
		score += 20

		factors = append(factors, "no_auth_required")
	}

	if score > 100 {
		score = 100
	}

	return score, factors
}
