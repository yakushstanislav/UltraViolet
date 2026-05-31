package probe

import (
	"crypto/dsa" //nolint:staticcheck // we only inspect key type, not negotiate
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLS finding severity levels.
const (
	tlsSeverityInfo     = "info"
	tlsSeverityLow      = "low"
	tlsSeverityMedium   = "medium"
	tlsSeverityHigh     = "high"
	tlsSeverityCritical = "critical"
)

// TLS finding codes.
const (
	tlsCodeExpired          = "expired"
	tlsCodeNotYetValid      = "not_yet_valid"
	tlsCodeExpiresSoon      = "expires_soon"
	tlsCodeSelfSigned       = "self_signed"
	tlsCodeHostnameMismatch = "hostname_mismatch"
	tlsCodeWeakProtocol     = "weak_protocol"
	tlsCodeWeakCipher       = "weak_cipher"
	tlsCodeShortKey         = "short_key"
	tlsCodeWeakSignature    = "weak_signature"
)

// tlsExpiresSoonWindow is the lead time for the expires_soon finding.
const tlsExpiresSoonWindow = 30 * 24 * time.Hour

// analyzeTLS evaluates the captured handshake against the security rule
// set and populates tlsResult.Findings + tlsResult.SecurityGrade. The
// leaf certificate is taken from state.PeerCertificates[0] (the same one
// leafCertToResult consumed) so callers don't need to plumb it separately.
func analyzeTLS(target Target, state *tls.ConnectionState, tlsResult *TLSResult) {
	if state == nil || len(state.PeerCertificates) == 0 || tlsResult == nil {
		return
	}

	leaf := state.PeerCertificates[0]
	findings := make([]TLSFinding, 0, 4)

	findings = appendCertValidityFindings(findings, leaf)
	findings = appendChainFindings(findings, leaf, state.PeerCertificates)
	findings = appendHostnameFindings(findings, leaf, target)
	findings = appendKeyFindings(findings, leaf)
	findings = appendSignatureFindings(findings, leaf)
	findings = appendProtocolFindings(findings, state.Version)
	findings = appendCipherFindings(findings, state.CipherSuite)

	tlsResult.Findings = findings
	tlsResult.SecurityGrade = gradeFromFindings(findings)
}

func appendCertValidityFindings(findings []TLSFinding, leaf *x509.Certificate) []TLSFinding {
	now := time.Now().UTC()

	switch {
	case now.After(leaf.NotAfter):
		findings = append(findings, TLSFinding{
			Severity: tlsSeverityCritical,
			Code:     tlsCodeExpired,
			Detail:   "certificate expired on " + leaf.NotAfter.Format(time.RFC3339),
		})
	case now.Add(tlsExpiresSoonWindow).After(leaf.NotAfter):
		findings = append(findings, TLSFinding{
			Severity: tlsSeverityLow,
			Code:     tlsCodeExpiresSoon,
			Detail:   "certificate expires on " + leaf.NotAfter.Format(time.RFC3339),
		})
	}

	if now.Before(leaf.NotBefore) {
		findings = append(findings, TLSFinding{
			Severity: tlsSeverityMedium,
			Code:     tlsCodeNotYetValid,
			Detail:   "certificate not valid until " + leaf.NotBefore.Format(time.RFC3339),
		})
	}

	return findings
}

func appendChainFindings(findings []TLSFinding, leaf *x509.Certificate, chain []*x509.Certificate) []TLSFinding {
	if leaf.Issuer.String() == leaf.Subject.String() && len(chain) == 1 {
		findings = append(findings, TLSFinding{
			Severity: tlsSeverityMedium,
			Code:     tlsCodeSelfSigned,
			Detail:   "leaf certificate is self-signed",
		})
	}

	return findings
}

func appendHostnameFindings(findings []TLSFinding, leaf *x509.Certificate, target Target) []TLSFinding {
	targetIP := net.ParseIP(target.IP.String())
	if targetIP == nil {
		return findings
	}

	for _, ip := range leaf.IPAddresses {
		if ip.Equal(targetIP) {
			return findings
		}
	}

	// Certificate exists for some DNS name(s) but we scanned by IP and the
	// IP is not in the SAN IPAddresses list — the cert does not cover this
	// peer. Common but worth flagging as a low-severity hint.
	findings = append(findings, TLSFinding{
		Severity: tlsSeverityLow,
		Code:     tlsCodeHostnameMismatch,
		Detail:   "scan IP not present in certificate SAN list",
	})

	return findings
}

func appendKeyFindings(findings []TLSFinding, leaf *x509.Certificate) []TLSFinding {
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			findings = append(findings, TLSFinding{
				Severity: tlsSeverityHigh,
				Code:     tlsCodeShortKey,
				Detail:   fmt.Sprintf("RSA key is %d bits (<2048)", pub.N.BitLen()),
			})
		}
	case *ecdsa.PublicKey:
		if pub.Params().BitSize < 256 {
			findings = append(findings, TLSFinding{
				Severity: tlsSeverityHigh,
				Code:     tlsCodeShortKey,
				Detail:   fmt.Sprintf("ECDSA curve is %d bits (<256)", pub.Params().BitSize),
			})
		}
	case ed25519.PublicKey:
		// Ed25519 is fixed at 256 bits and always considered strong.
	case *dsa.PublicKey:
		findings = append(findings, TLSFinding{
			Severity: tlsSeverityHigh,
			Code:     tlsCodeShortKey,
			Detail:   "DSA key (deprecated)",
		})
	}

	return findings
}

func appendSignatureFindings(findings []TLSFinding, leaf *x509.Certificate) []TLSFinding {
	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		findings = append(findings, TLSFinding{
			Severity: tlsSeverityHigh,
			Code:     tlsCodeWeakSignature,
			Detail:   "certificate signed with " + leaf.SignatureAlgorithm.String(),
		})
	}

	return findings
}

func appendProtocolFindings(findings []TLSFinding, version uint16) []TLSFinding {
	switch version {
	case tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11: //nolint:staticcheck // intentionally checking deprecated versions
		findings = append(findings, TLSFinding{
			Severity: tlsSeverityHigh,
			Code:     tlsCodeWeakProtocol,
			Detail:   "negotiated " + tls.VersionName(version),
		})
	}

	return findings
}

func appendCipherFindings(findings []TLSFinding, suite uint16) []TLSFinding {
	name := strings.ToUpper(tls.CipherSuiteName(suite))

	for _, marker := range []string{"RC4", "3DES", "DES_", "EXPORT", "NULL", "ANON"} {
		if strings.Contains(name, marker) {
			findings = append(findings, TLSFinding{
				Severity: tlsSeverityHigh,
				Code:     tlsCodeWeakCipher,
				Detail:   "negotiated " + tls.CipherSuiteName(suite),
			})

			break
		}
	}

	return findings
}

// gradeFromFindings collapses the finding set into a letter grade. The
// thresholds match the rationale in the PR 3 design: F covers anything
// catastrophic, C signals fixable but real risk, B is a quibble or two,
// A is clean.
func gradeFromFindings(findings []TLSFinding) string {
	var critical, high, medium int

	for _, f := range findings {
		switch f.Severity {
		case tlsSeverityCritical:
			critical++
		case tlsSeverityHigh:
			high++
		case tlsSeverityMedium:
			medium++
		}
	}

	switch {
	case critical > 0 || high >= 3:
		return "F"
	case high > 0 || medium > 2:
		return "C"
	case medium > 0:
		return "B"
	default:
		return "A"
	}
}
