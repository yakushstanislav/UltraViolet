package topology

import (
	"sort"

	dashboarddto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/dashboard"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/countrycentroid"
)

type weightedCountry struct {
	countryCode string
	count       uint64
	lat         float64
	lng         float64
}

func buildCentroidFallbackPoints(
	countries []dashboarddto.CountryRow,
	limit int,
) []dashboarddto.PointRow {
	if limit <= 0 || len(countries) == 0 {
		return nil
	}

	weighted := make([]weightedCountry, 0, len(countries))

	var totalHosts uint64

	for _, row := range countries {
		if row.Count == 0 {
			continue
		}

		lat, lng, ok := countrycentroid.Lookup(row.CountryCode)
		if !ok {
			continue
		}

		weighted = append(weighted, weightedCountry{
			countryCode: row.CountryCode,
			count:       row.Count,
			lat:         lat,
			lng:         lng,
		})
		totalHosts += row.Count
	}

	if len(weighted) == 0 || totalHosts == 0 {
		return nil
	}

	sort.Slice(weighted, func(i, j int) bool {
		return weighted[i].count > weighted[j].count
	})

	out := make([]dashboarddto.PointRow, 0, limit)
	remaining := limit

	for _, row := range weighted {
		if remaining <= 0 {
			break
		}

		share := int((row.count * uint64(limit)) / totalHosts)
		if share < 1 {
			share = 1
		}

		if share > remaining {
			share = remaining
		}

		hostCap := int(row.count)
		if hostCap > 0 && share > hostCap {
			share = hostCap
		}

		for i := 0; i < share; i++ {
			jlat, jlng := countrycentroid.Jitter(row.lat, row.lng, row.countryCode, i)

			out = append(out, dashboarddto.PointRow{
				Latitude:    jlat,
				Longitude:   jlng,
				CountryCode: row.countryCode,
			})
		}

		remaining -= share
	}

	return out
}
