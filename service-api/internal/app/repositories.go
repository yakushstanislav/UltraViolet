// Package app holds shared composition-root wiring used by both the API and
// scanner binaries: the repository aggregate and helpers to build it.
package app

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/ingest"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/attackpath"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/audit"
	cpemaprepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cpemap"
	cvecatalog "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/catalog"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	cvematchstate "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/matchstate"
	cvesyncstate "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/syncstate"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/dns"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/alert"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/delta"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/savedsearch"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpresponse"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpscreenshot"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpsecurity"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/pivot"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/refreshtoken"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/remediation"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/riskpolicy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/risksnapshot"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scanschedule"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/search"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/smtpinfo"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/sshinfo"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/user"
)

// Repositories aggregates every persistence-layer interface used by the
// service. Constructing this once at startup keeps the binaries' wiring small
// and consistent.
type Repositories struct {
	Host               host.Repository
	Service            service.Repository
	HTTPResponse       httpresponse.Repository
	HTTPScreenshot     httpscreenshot.Repository
	HTTPSecurity       httpsecurity.Repository
	TLSCertificate     tlscertificate.Repository
	ServiceFingerprint servicefingerprint.Repository
	DNS                dns.Repository
	SSHInfo            sshinfo.Repository
	SMTPInfo           smtpinfo.Repository
	Scan               scan.Repository
	ScanSchedule       scanschedule.Repository
	Search             search.Repository
	SavedSearch        savedsearch.Repository
	Delta              delta.Repository
	Alert              alert.Repository
	Audit              audit.Repository
	User               user.Repository
	RefreshToken       refreshtoken.Repository
	CPEProductMap      cpemaprepository.Repository
	CVECatalog         cvecatalog.Repository
	CVEMatch           cvematch.Repository
	CVEMatchState      cvematchstate.Repository
	CVESyncState       cvesyncstate.Repository
	Pivot              pivot.Repository
	RiskPolicy         riskpolicy.Repository
	RiskSnapshot       risksnapshot.Repository
	AttackPath         attackpath.Repository
	Remediation        remediation.Repository
}

// NewRepositories builds every repository against the shared pgx pool.
func NewRepositories(pool *pgxpool.Pool) *Repositories {
	return &Repositories{
		Host:               host.NewPostgreSQL(pool),
		Service:            service.NewPostgreSQL(pool),
		HTTPResponse:       httpresponse.NewPostgreSQL(pool),
		HTTPScreenshot:     httpscreenshot.NewPostgreSQL(pool),
		HTTPSecurity:       httpsecurity.NewPostgreSQL(pool),
		TLSCertificate:     tlscertificate.NewPostgreSQL(pool),
		ServiceFingerprint: servicefingerprint.NewPostgreSQL(pool),
		DNS:                dns.NewPostgreSQL(pool),
		SSHInfo:            sshinfo.NewPostgreSQL(pool),
		SMTPInfo:           smtpinfo.NewPostgreSQL(pool),
		Scan:               scan.NewPostgreSQL(pool),
		ScanSchedule:       scanschedule.NewPostgreSQL(pool),
		Search:             search.NewPostgreSQL(pool),
		SavedSearch:        savedsearch.NewPostgreSQL(pool),
		Delta:              delta.NewPostgreSQL(pool),
		Alert:              alert.NewPostgreSQL(pool),
		Audit:              audit.NewPostgreSQL(pool),
		User:               user.NewPostgreSQL(pool),
		RefreshToken:       refreshtoken.NewPostgreSQL(pool),
		CPEProductMap:      cpemaprepository.NewPostgreSQLProductMap(pool),
		CVECatalog:         cvecatalog.NewPostgreSQL(pool),
		CVEMatch:           cvematch.NewPostgreSQL(pool),
		CVEMatchState:      cvematchstate.NewPostgreSQL(pool),
		CVESyncState:       cvesyncstate.NewPostgreSQL(pool),
		Pivot:              pivot.NewPostgreSQL(pool),
		RiskPolicy:         riskpolicy.NewPostgreSQL(pool),
		RiskSnapshot:       risksnapshot.NewPostgreSQL(pool),
		AttackPath:         attackpath.NewPostgreSQL(pool),
		Remediation:        remediation.NewPostgreSQL(pool),
	}
}

// IngestRepositories returns the subset of repositories needed by the
// scanner's ingest pipeline.
func (r *Repositories) IngestRepositories() ingest.Repositories {
	return ingest.Repositories{
		Host:               r.Host,
		Service:            r.Service,
		HTTPResponse:       r.HTTPResponse,
		HTTPScreenshot:     r.HTTPScreenshot,
		HTTPSecurity:       r.HTTPSecurity,
		TLSCertificate:     r.TLSCertificate,
		ServiceFingerprint: r.ServiceFingerprint,
		SSHInfo:            r.SSHInfo,
		SMTPInfo:           r.SMTPInfo,
	}
}
