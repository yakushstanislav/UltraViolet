// Package topology answers the geographic/ASN distribution and top-N
// aggregates the dashboard shows (countries, ASNs, ports, protocols, TLS
// issuers).
package topology

import (
	"context"

	"golang.org/x/sync/errgroup"

	dashboarddto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/dashboard"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nullable"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
)

const defaultGlobePointsLimit = 800

// Service answers GET /dashboard/map and GET /dashboard/top.
type Service struct {
	hosts    host.Repository
	services service.Repository
	tlsCerts tlscertificate.Repository
}

// New builds a Service.
func New(
	hosts host.Repository,
	services service.Repository,
	tlsCerts tlscertificate.Repository,
) *Service {
	return &Service{hosts: hosts, services: services, tlsCerts: tlsCerts}
}

// Map returns the country distribution and geo host points for the dashboard globe.
func (s *Service) Map(ctx context.Context) (dashboarddto.MapResponse, error) {
	var (
		countryRows []host.CountryBucket
		geoRows     []host.GeoHostPoint
	)

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		out, err := s.hosts.GetHostCountByCountry(groupCtx)
		if err != nil {
			return err
		}

		countryRows = out

		return nil
	})

	group.Go(func() error {
		out, err := s.hosts.ListGeoHosts(groupCtx, defaultGlobePointsLimit)
		if err != nil {
			return err
		}

		geoRows = out

		return nil
	})

	if err := group.Wait(); err != nil {
		return dashboarddto.MapResponse{}, err
	}

	countries := make([]dashboarddto.CountryRow, 0, len(countryRows))
	for _, row := range countryRows {
		countries = append(countries, dashboarddto.CountryRow{
			CountryCode: row.CountryCode,
			Count:       row.Count,
		})
	}

	points := make([]dashboarddto.PointRow, 0, len(geoRows))
	for _, row := range geoRows {
		points = append(points, dashboarddto.PointRow{
			Latitude:    row.Latitude,
			Longitude:   row.Longitude,
			CountryCode: row.CountryCode,
		})
	}

	pointsSource := dashboarddto.MapPointsSourceGeo
	if len(points) == 0 && len(countries) > 0 {
		points = buildCentroidFallbackPoints(countries, defaultGlobePointsLimit)
		if len(points) > 0 {
			pointsSource = dashboarddto.MapPointsSourceCountryCentroid
		}
	}

	return dashboarddto.MapResponse{
		Countries:    countries,
		Points:       points,
		PointsSource: pointsSource,
	}, nil
}

// Top fans out the various top-N aggregates in parallel.
func (s *Service) Top(ctx context.Context, limit uint64) (dashboarddto.TopResponse, error) {
	var (
		ports       []service.PortBucket
		protocols   []service.ProtocolBucket
		asnRows     []host.ASNBucket
		countryRows []host.CountryBucket
		issuers     []tlscertificate.IssuerBucket
	)

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		out, err := s.services.TopPorts(groupCtx, limit)
		if err != nil {
			return err
		}

		ports = out

		return nil
	})

	group.Go(func() error {
		out, err := s.services.TopProtocols(groupCtx, limit)
		if err != nil {
			return err
		}

		protocols = out

		return nil
	})

	group.Go(func() error {
		out, err := s.hosts.TopASN(groupCtx, limit)
		if err != nil {
			return err
		}

		asnRows = out

		return nil
	})

	group.Go(func() error {
		out, err := s.hosts.GetHostCountByCountry(groupCtx)
		if err != nil {
			return err
		}

		countryRows = out

		return nil
	})

	group.Go(func() error {
		out, err := s.tlsCerts.TopIssuers(groupCtx, limit)
		if err != nil {
			return err
		}

		issuers = out

		return nil
	})

	if err := group.Wait(); err != nil {
		return dashboarddto.TopResponse{}, err
	}

	return buildTopResponse(limit, ports, protocols, asnRows, countryRows, issuers), nil
}

func buildTopResponse(
	limit uint64,
	ports []service.PortBucket,
	protocols []service.ProtocolBucket,
	asnRows []host.ASNBucket,
	countryRows []host.CountryBucket,
	issuers []tlscertificate.IssuerBucket,
) dashboarddto.TopResponse {
	out := dashboarddto.TopResponse{
		Limit:         limit,
		TopPorts:      make([]dashboarddto.PortRow, 0, len(ports)),
		TopProtocols:  make([]dashboarddto.ProtocolRow, 0, len(protocols)),
		TopASN:        make([]dashboarddto.ASNRow, 0, len(asnRows)),
		TopCountries:  make([]dashboarddto.TopCountryRow, 0, limit),
		TopTLSIssuers: make([]dashboarddto.TLSIssuerRow, 0, len(issuers)),
	}

	for _, p := range ports {
		out.TopPorts = append(out.TopPorts, dashboarddto.PortRow{Port: p.Port, Count: p.Count})
	}

	for _, pr := range protocols {
		out.TopProtocols = append(out.TopProtocols, dashboarddto.ProtocolRow{Protocol: pr.Protocol, Count: pr.Count})
	}

	for _, a := range asnRows {
		out.TopASN = append(out.TopASN, dashboarddto.ASNRow{
			ASN:    a.ASN,
			ASNOrg: nullable.String(a.ASNOrg),
			Count:  a.Count,
		})
	}

	for i, c := range countryRows {
		if uint64(i) >= limit {
			break
		}

		out.TopCountries = append(out.TopCountries, dashboarddto.TopCountryRow{
			CountryCode: c.CountryCode,
			Count:       c.Count,
		})
	}

	for _, is := range issuers {
		out.TopTLSIssuers = append(out.TopTLSIssuers, dashboarddto.TLSIssuerRow{
			Issuer: is.Issuer,
			Count:  is.Count,
		})
	}

	return out
}
