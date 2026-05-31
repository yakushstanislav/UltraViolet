// Package ingest persists scanner probe results into domain repositories in
// a single transaction so partial writes never escape on failure.
package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/geoip"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nullable"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/probe"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/utf8safe"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpresponse"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpscreenshot"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpsecurity"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/smtpinfo"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/sshinfo"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
)

// CVEMatcher matches CVEs for a single service against the local catalog.
// Implementations may be called concurrently from the scanner pipeline.
type CVEMatcher interface {
	MatchService(ctx context.Context, serviceID uint64) (int, error)
}

// Repositories are the storage dependencies used by Ingestor. Each field is
// an interface so the Ingestor can call WithTx to rebind writes to a shared
// transaction without depending on concrete types.
type Repositories struct {
	Host               host.Repository
	Service            servicerepository.Repository
	HTTPResponse       httpresponse.Repository
	HTTPScreenshot     httpscreenshot.Repository
	HTTPSecurity       httpsecurity.Repository
	TLSCertificate     tlscertificate.Repository
	ServiceFingerprint servicefingerprint.Repository
	SSHInfo            sshinfo.Repository
	SMTPInfo           smtpinfo.Repository
}

// Ingestor writes probe results into PostgreSQL inside a single transaction.
type Ingestor struct {
	pool         *pgxpool.Pool
	repositories Repositories
}

// New builds an Ingestor.
func New(pool *pgxpool.Pool, repositories Repositories) *Ingestor {
	return &Ingestor{pool: pool, repositories: repositories}
}

// Ingest upserts host, service and protocol-specific metadata for one probe
// result atomically. Returns the persisted service ID, host ID, and whether the
// fingerprint changed — callers use the latter to schedule CVE matching.
// If any step fails the entire transaction is rolled back.
func (i *Ingestor) Ingest(ctx context.Context, result *probe.Result, geo geoip.Result) (uint64, uint64, bool, error) {
	if result == nil {
		return 0, 0, false, errors.New("probe result is nil")
	}

	tx, err := i.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, 0, false, fmt.Errorf("can't begin ingest transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	serviceID, hostID, fingerprintChanged, err := i.ingestInTx(ctx, tx, result, geo)
	if err != nil {
		return 0, 0, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, false, fmt.Errorf("can't commit ingest transaction: %w", err)
	}

	return serviceID, hostID, fingerprintChanged, nil
}

func (i *Ingestor) ingestInTx(ctx context.Context, tx pgx.Tx, result *probe.Result, geo geoip.Result) (uint64, uint64, bool, error) {
	hostRepository := i.repositories.Host.WithTx(tx)
	serviceRepository := i.repositories.Service.WithTx(tx)

	now := time.Now().UTC()

	hostID, err := hostRepository.Upsert(ctx, &host.Host{
		IP:          result.Target.IP,
		CountryCode: nullable.StringPtr(utf8safe.Sanitize(geo.CountryCode)),
		CountryName: nullable.StringPtr(utf8safe.Sanitize(geo.CountryName)),
		City:        nullable.StringPtr(utf8safe.Sanitize(geo.City)),
		Latitude:    nullable.Float64Ptr(geo.Latitude, geo.HasLocation),
		Longitude:   nullable.Float64Ptr(geo.Longitude, geo.HasLocation),
		ASN:         nullable.Int64Ptr(geo.ASN, geo.HasASN),
		ASNOrg:      nullable.StringPtr(utf8safe.Sanitize(geo.ASNOrg)),
		LastSeen:    now,
	})
	if err != nil {
		return 0, 0, false, fmt.Errorf("can't ingest host: %w", err)
	}

	transport := servicerepository.TransportTCP
	if result.Target.Transport == probe.TransportUDP {
		transport = servicerepository.TransportUDP
	}

	serviceID, err := serviceRepository.Upsert(ctx, &servicerepository.Service{
		HostID:     hostID,
		Port:       result.Target.Port,
		Transport:  transport,
		Protocol:   nullUTF8(result.Protocol),
		Banner:     nullUTF8(result.Banner),
		BannerHash: nullable.NullString(result.BannerHash()),
		LastSeen:   now,
	})
	if err != nil {
		return 0, 0, false, fmt.Errorf("can't ingest service: %w", err)
	}

	if result.HTTP != nil {
		httpRepository := i.repositories.HTTPResponse.WithTx(tx)

		var faviconHash sql.NullInt32
		if result.HTTP.FaviconHash != nil {
			faviconHash = sql.NullInt32{Int32: *result.HTTP.FaviconHash, Valid: true}
		}

		chain := make([]httpresponse.RedirectStep, 0, len(result.HTTP.RedirectChain))
		for _, step := range result.HTTP.RedirectChain {
			chain = append(chain, httpresponse.RedirectStep{
				URL:        utf8safe.Sanitize(step.URL),
				StatusCode: step.StatusCode,
				Location:   utf8safe.Sanitize(step.Location),
			})
		}

		bodySHA256 := nullable.NullString(result.HTTP.BodySHA256)

		err := httpRepository.Upsert(ctx, &httpresponse.HTTPResponse{
			ServiceID:      serviceID,
			StatusCode:     nullable.NullInt32(int32(result.HTTP.StatusCode), result.HTTP.StatusCode != 0),
			ServerHeader:   nullUTF8(result.HTTP.Server),
			Title:          nullUTF8(result.HTTP.Title),
			Headers:        utf8safe.SanitizeMapString(result.HTTP.Headers),
			Body:           nullUTF8(result.HTTP.Body),
			FaviconHash:    faviconHash,
			Technologies:   utf8safe.SanitizeStrings(result.HTTP.Technologies),
			RedirectURL:    nullUTF8(result.HTTP.RedirectURL),
			RedirectChain:  chain,
			RobotsTxt:      nullUTF8(result.HTTP.RobotsTxt),
			SecurityTxt:    nullUTF8(result.HTTP.SecurityTxt),
			BodySHA256:     bodySHA256,
			NotFoundHash:   nullable.NullString(result.HTTP.NotFoundHash),
			AltSvcRaw:      nullUTF8(result.HTTP.AltSvcRaw),
			HTTP3Supported: result.HTTP.HTTP3Supported,
			CapturedAt:     now,
		})
		if err != nil {
			return 0, 0, false, fmt.Errorf("can't ingest HTTP response: %w", err)
		}

		if i.repositories.HTTPScreenshot != nil {
			httpScreenshotRepository := i.repositories.HTTPScreenshot.WithTx(tx)

			if err := httpScreenshotRepository.EnqueueIfStale(ctx, serviceID, bodySHA256); err != nil {
				return 0, 0, false, fmt.Errorf("can't enqueue HTTP screenshot job: %w", err)
			}
		}

		if result.HTTP.Security != nil && i.repositories.HTTPSecurity != nil {
			securityRepository := i.repositories.HTTPSecurity.WithTx(tx)

			sec := result.HTTP.Security

			err := securityRepository.Upsert(ctx, &httpsecurity.HTTPSecurity{
				ServiceID:                serviceID,
				HSTSMaxAge:               nullable.NullInt64(sec.HSTSMaxAge, sec.HSTSMaxAge > 0),
				HSTSIncludeSubdomains:    sec.HSTSIncludeSubdomains,
				HSTSPreload:              sec.HSTSPreload,
				CSPPresent:               sec.CSPPresent,
				CSPHasUnsafeInline:       sec.CSPHasUnsafeInline,
				CSPHasUnsafeEval:         sec.CSPHasUnsafeEval,
				XFrameOptions:            nullUTF8(sec.XFrameOptions),
				XContentTypeOptions:      nullUTF8(sec.XContentTypeOptions),
				ReferrerPolicy:           nullUTF8(sec.ReferrerPolicy),
				PermissionsPolicyPresent: sec.PermissionsPolicyPresent,
				CORSAllowOrigin:          nullUTF8(sec.CORSAllowOrigin),
				CookieSecureCount:        sec.CookieSecureCount,
				CookieHTTPOnlyCount:      sec.CookieHTTPOnlyCount,
				CookieSameSiteStrict:     sec.CookieSameSiteStrict,
				CookieSameSiteLax:        sec.CookieSameSiteLax,
				CookieSameSiteNone:       sec.CookieSameSiteNone,
				CapturedAt:               now,
			})
			if err != nil {
				return 0, 0, false, fmt.Errorf("can't ingest HTTP security: %w", err)
			}
		}
	}

	if result.TLS != nil {
		tlsRepository := i.repositories.TLSCertificate.WithTx(tx)

		err := tlsRepository.Upsert(ctx, &tlscertificate.TLSCertificate{
			ServiceID:         serviceID,
			Subject:           nullUTF8(result.TLS.Subject),
			Issuer:            nullUTF8(result.TLS.Issuer),
			FingerprintSHA256: nullUTF8(result.TLS.FingerprintSHA256),
			NotBefore:         nullable.NullTime(result.TLS.NotBefore),
			NotAfter:          nullable.NullTime(result.TLS.NotAfter),
			RawPEM:            nullUTF8(result.TLS.RawPEM),
			SANs:              utf8safe.SanitizeStrings(result.TLS.SANs),
			JARMFingerprint:   nullUTF8(result.TLS.JARMFingerprint),
			TLSVersion:        nullUTF8(result.TLS.TLSVersion),
			CipherSuite:       nullUTF8(result.TLS.CipherSuite),
			JA3SHash:          nullUTF8(result.TLS.JA3SHash),
			JA4SHash:          nullUTF8(result.TLS.JA4SHash),
			SecurityGrade:     nullable.NullString(result.TLS.SecurityGrade),
		})
		if err != nil {
			return 0, 0, false, fmt.Errorf("can't ingest TLS certificate: %w", err)
		}

		findings := make([]tlscertificate.TLSFinding, 0, len(result.TLS.Findings))

		for _, f := range result.TLS.Findings {
			findings = append(findings, tlscertificate.TLSFinding{
				ServiceID:  serviceID,
				Severity:   f.Severity,
				Code:       f.Code,
				Detail:     nullUTF8(f.Detail),
				CapturedAt: now,
			})
		}

		if err := tlsRepository.UpsertFindings(ctx, serviceID, findings); err != nil {
			return 0, 0, false, fmt.Errorf("can't ingest TLS findings: %w", err)
		}

		if len(result.TLS.Chain) > 0 {
			nodes := make([]tlscertificate.TLSChainNode, 0, len(result.TLS.Chain))

			for idx, node := range result.TLS.Chain {
				nodes = append(nodes, tlscertificate.TLSChainNode{
					ServiceID:         serviceID,
					ChainPosition:     idx + 1,
					Subject:           nullUTF8(node.Subject),
					Issuer:            nullUTF8(node.Issuer),
					FingerprintSHA256: nullUTF8(node.FingerprintSHA256),
					NotBefore:         nullable.NullTime(node.NotBefore),
					NotAfter:          nullable.NullTime(node.NotAfter),
					RawPEM:            nullUTF8(node.RawPEM),
					SANs:              utf8safe.SanitizeStrings(node.SANs),
					CapturedAt:        now,
				})
			}

			if err := tlsRepository.UpsertChain(ctx, serviceID, nodes); err != nil {
				return 0, 0, false, fmt.Errorf("can't ingest TLS chain: %w", err)
			}
		}
	}

	if result.SSH != nil && i.repositories.SSHInfo != nil {
		sshRepository := i.repositories.SSHInfo.WithTx(tx)

		err := sshRepository.Upsert(ctx, &sshinfo.SSHInfo{
			ServiceID:          serviceID,
			ServerVersion:      nullUTF8(result.SSH.ServerVersion),
			HostKeyType:        nullUTF8(result.SSH.HostKeyType),
			HostKeyFingerprint: nullUTF8(result.SSH.HostKeyFingerprint),
			KexAlgorithms:      utf8safe.SanitizeStrings(result.SSH.KexAlgorithms),
			HostKeyAlgorithms:  utf8safe.SanitizeStrings(result.SSH.HostKeyAlgorithms),
			CapturedAt:         now,
		})
		if err != nil {
			return 0, 0, false, fmt.Errorf("can't ingest SSH info: %w", err)
		}
	}

	if result.SMTP != nil && i.repositories.SMTPInfo != nil {
		smtpRepository := i.repositories.SMTPInfo.WithTx(tx)

		err := smtpRepository.Upsert(ctx, &smtpinfo.SMTPInfo{
			ServiceID:      serviceID,
			Banner:         nullUTF8(result.SMTP.Banner),
			Capabilities:   utf8safe.SanitizeStrings(result.SMTP.Capabilities),
			STARTTLS:       result.SMTP.STARTTLS,
			AuthMethods:    utf8safe.SanitizeStrings(result.SMTP.AuthMethods),
			MaxMessageSize: nullable.NullInt64(result.SMTP.MaxMessageSize, result.SMTP.MaxMessageSize > 0),
			CapturedAt:     now,
		})
		if err != nil {
			return 0, 0, false, fmt.Errorf("can't ingest SMTP info: %w", err)
		}
	}

	fingerprintChanged := false

	if i.repositories.ServiceFingerprint != nil {
		components := collectComponents(result)

		if len(components) > 0 {
			fingerprintRepository := i.repositories.ServiceFingerprint.WithTx(tx)

			fps := make([]*servicefingerprint.Fingerprint, 0, len(components))

			for _, comp := range components {
				fps = append(fps, &servicefingerprint.Fingerprint{
					ServiceID:    serviceID,
					Product:      utf8safe.Sanitize(comp.Product),
					Version:      nullUTF8(comp.Version),
					Edition:      nullUTF8(comp.Edition),
					Source:       comp.Source,
					Role:         nullUTF8(comp.Role),
					ClusterRole:  nullUTF8(comp.ClusterRole),
					ClusterName:  nullUTF8(comp.ClusterName),
					AuthRequired: nullable.NullBool(comp.AuthRequired),
					TLSRequired:  nullable.NullBool(comp.TLSRequired),
					Anonymous:    comp.Anonymous,
					RawJSON:      comp.RawJSON,
					CapturedAt:   now,
				})
			}

			if err := fingerprintRepository.ReplaceAllForService(ctx, serviceID, fps); err != nil {
				return 0, 0, false, fmt.Errorf("can't ingest service fingerprints: %w", err)
			}

			fingerprintChanged = true
		}
	}

	return serviceID, hostID, fingerprintChanged, nil
}

// collectComponents merges result.Components (full multi-layer stack from
// HTTP probes) with the legacy result.Fingerprint (specialized probes that
// haven't been ported to components yet) into the final write set. The
// primary Fingerprint is tagged source=protocol_probe so it stays
// distinguishable from header-derived components.
func collectComponents(result *probe.Result) []probe.TechComponent {
	components := make([]probe.TechComponent, 0, len(result.Components)+1)

	if len(result.Components) > 0 {
		components = append(components, result.Components...)
	}

	if result.Fingerprint != nil {
		legacy := probe.TechComponent{
			Product:      result.Fingerprint.Product,
			Version:      result.Fingerprint.Version,
			Edition:      result.Fingerprint.Edition,
			ClusterRole:  result.Fingerprint.ClusterRole,
			ClusterName:  result.Fingerprint.ClusterName,
			AuthRequired: result.Fingerprint.AuthRequired,
			TLSRequired:  result.Fingerprint.TLSRequired,
			Anonymous:    result.Fingerprint.Anonymous,
			RawJSON:      result.Fingerprint.RawJSON,
			Source:       probe.ComponentSourceProtocolProbe,
		}

		alreadyPresent := false

		for _, existing := range components {
			if existing.Product == legacy.Product && existing.Source == legacy.Source {
				alreadyPresent = true

				break
			}
		}

		if !alreadyPresent {
			components = append(components, legacy)
		}
	}

	filtered := components[:0]

	for _, comp := range components {
		if comp.Product == "" {
			continue
		}

		if comp.Source == "" {
			comp.Source = probe.ComponentSourceProtocolProbe
		}

		// Last-resort version capture: when a specialized probe identified
		// the product but couldn't pull a version through the protocol's
		// own version field, try to extract one from the raw banner so the
		// CVE matcher can do a range comparison instead of falling back to
		// the version-less catch-all path.
		if comp.Version == "" && result.Banner != "" {
			comp.Version = probe.ExtractVersionFromBanner(result.Banner)
		}

		filtered = append(filtered, comp)
	}

	return filtered
}

func nullUTF8(s string) sql.NullString {
	return nullable.NullString(utf8safe.Sanitize(s))
}
