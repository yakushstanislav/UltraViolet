package dashboard

// CountryRow is one country bucket for GET /v1/dashboard/map.
type CountryRow struct {
	CountryCode string `json:"country_code"`
	Count       uint64 `json:"count"`
}

// PointRow is one host with geo coordinates for the dashboard 3D globe.
type PointRow struct {
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	CountryCode string  `json:"country_code,omitempty"`
}

// Map points source values for PointsSource.
const (
	MapPointsSourceGeo             = "geo"
	MapPointsSourceCountryCentroid = "country_centroid"
)

// MapResponse is the wire format of GET /v1/dashboard/map.
type MapResponse struct {
	Countries    []CountryRow `json:"countries"`
	Points       []PointRow   `json:"points"`
	PointsSource string       `json:"points_source,omitempty"`
}
