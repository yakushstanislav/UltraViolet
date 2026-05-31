// Package countrycentroid resolves ISO country codes to reference map coordinates.
package countrycentroid

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

//go:embed country_centroids.json
var centroidsJSON []byte

var centroids map[string][2]float64

func init() {
	if err := json.Unmarshal(centroidsJSON, &centroids); err != nil {
		panic(fmt.Sprintf("countrycentroid: can't parse embedded centroids: %v", err))
	}
}

// NormalizeCode normalizes API country_code to ISO 3166-1 alpha-2 for lookup.
func NormalizeCode(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}

	if s == "UK" {
		return "GB"
	}

	if len(s) > 2 {
		s = s[:2]
	}

	if len(s) != 2 {
		return ""
	}

	return s
}

// Lookup returns reference coordinates for a country code.
func Lookup(countryCode string) (lat float64, lng float64, ok bool) {
	code := NormalizeCode(countryCode)
	if code == "" {
		return 0, 0, false
	}

	pair, found := centroids[code]
	if !found {
		return 0, 0, false
	}

	return pair[0], pair[1], true
}

// Jitter offsets a centroid slightly so multiple synthetic hosts do not stack.
func Jitter(lat, lng float64, countryCode string, index int) (float64, float64) {
	code := NormalizeCode(countryCode)
	seed := uint32(0)

	for i := 0; i < len(code); i++ {
		seed = seed*31 + uint32(code[i])
	}

	angle := float64((seed*2654435761 + uint32(index)*9747) % 6283)
	angle /= 1000.0

	radius := 0.12 + float64(index%9)*0.07
	dlat := radius * math.Cos(angle) * 0.65
	dlng := radius * math.Sin(angle) / math.Max(0.35, math.Cos(lat*math.Pi/180))

	return lat + dlat, lng + dlng
}
