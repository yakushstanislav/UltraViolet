// Package geoip performs offline IP lookups using MaxMind DB (MMDB) readers.
//
// Supported databases:
//   - IPLocate.io free IP-to-country and IP-to-ASN MMDB (CC BY-SA 4.0, attribution required)
//   - MaxMind GeoLite2 City or Country + GeoLite2 ASN (optional legacy)
//
// If GEOIP_* paths are empty, Open tries standard filenames under /geoip
// (docker-compose bind mount). Lookup is a no-op when no databases are open.
package geoip

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/countryprefix"
)

// Config holds MMDB paths (names are legacy: "city" is the country/geolocation DB).
type Config struct {
	CityPath string `env:"GEOIP_CITY_PATH"`
	ASNPath  string `env:"GEOIP_ASN_PATH"`
}

// Result is what a Lookup returns.
type Result struct {
	CountryCode string
	CountryName string
	City        string
	Latitude    float64
	Longitude   float64
	HasLocation bool
	ASN         int64
	HasASN      bool
	ASNOrg      string
}

// DB holds MMDB readers for country-level (or City) and ASN data.
type DB struct {
	country       *maxminddb.Reader
	asn           *maxminddb.Reader
	countryLayout recordLayout
	asnLayout     recordLayout
}

type recordLayout uint8

const (
	layoutNone recordLayout = iota
	layoutIPLocateCountry
	layoutIPLocateASN
	layoutMaxMindCity
	layoutMaxMindCountry
	layoutMaxMindASN
)

// Open opens the configured databases. Either path may be empty.
func Open(config *Config) (*DB, error) {
	db := &DB{}

	countryPath := resolveCountryMMDBPath(config.CityPath)
	asnPath := resolveASNMMDBPath(config.ASNPath)

	if countryPath != "" {
		reader, err := maxminddb.Open(countryPath)
		if err != nil {
			return nil, fmt.Errorf("can't open GeoIP country/city database: %w", err)
		}

		db.country = reader
		db.countryLayout = detectCountryLayout(reader)

		if db.countryLayout == layoutNone {
			db.Close()

			return nil, unsupportedMMDBError(
				"country/geolocation",
				reader.Metadata.DatabaseType,
				countryPath,
			)
		}
	}

	if asnPath != "" {
		reader, err := maxminddb.Open(asnPath)
		if err != nil {
			db.Close()

			return nil, fmt.Errorf("can't open GeoIP ASN database: %w", err)
		}

		db.asn = reader
		db.asnLayout = detectASNLayout(reader)

		if db.asnLayout == layoutNone {
			db.Close()

			return nil, unsupportedMMDBError(
				"asn",
				reader.Metadata.DatabaseType,
				asnPath,
			)
		}
	}

	return db, nil
}

func unsupportedMMDBError(role, databaseType, path string) error {
	return fmt.Errorf(
		"unsupported %s MMDB (database_type=%q, path=%s): use IPLocate ip-to-country.mmdb / ip-to-asn.mmdb, "+
			"GeoLite2-City or GeoLite2-Country + GeoLite2-ASN, with exact filenames under /geoip in Docker or set GEOIP_CITY_PATH / GEOIP_ASN_PATH",
		role,
		databaseType,
		path,
	)
}

func detectCountryLayout(r *maxminddb.Reader) recordLayout {
	if r == nil {
		return layoutNone
	}

	dt := strings.ToLower(r.Metadata.DatabaseType)

	if strings.Contains(dt, "iplocate") && strings.Contains(dt, "country") {
		return layoutIPLocateCountry
	}

	if strings.Contains(dt, "city") {
		return layoutMaxMindCity
	}

	if strings.Contains(dt, "country") {
		return layoutMaxMindCountry
	}

	return layoutNone
}

func detectASNLayout(r *maxminddb.Reader) recordLayout {
	if r == nil {
		return layoutNone
	}

	dt := strings.ToLower(r.Metadata.DatabaseType)

	if strings.Contains(dt, "iplocate") && strings.Contains(dt, "asn") {
		return layoutIPLocateASN
	}

	if strings.Contains(dt, "asn") {
		return layoutMaxMindASN
	}

	return layoutNone
}

func geoipSearchDirs() []string {
	dirs := make([]string, 0, 3)
	dirs = append(dirs, "/geoip")

	wd, err := os.Getwd()
	if err == nil {
		dirs = append(dirs,
			filepath.Join(wd, "geoip"),
			filepath.Join(wd, "service-env", "geoip"),
		)
	}

	return dirs
}

func resolveCountryMMDBPath(configured string) string {
	if configured != "" {
		return configured
	}

	names := []string{
		"ip-to-country.mmdb",
		"GeoLite2-City.mmdb",
		"GeoLite2-Country.mmdb",
	}

	for _, dir := range geoipSearchDirs() {
		for _, name := range names {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}

	return ""
}

func resolveASNMMDBPath(configured string) string {
	if configured != "" {
		return configured
	}

	names := []string{
		"ip-to-asn.mmdb",
		"GeoLite2-ASN.mmdb",
	}

	for _, dir := range geoipSearchDirs() {
		for _, name := range names {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}

	return ""
}

// Close releases the underlying readers. Nil-safe.
func (d *DB) Close() {
	if d == nil {
		return
	}

	if d.country != nil {
		_ = d.country.Close()
	}

	if d.asn != nil {
		_ = d.asn.Close()
	}
}

type iplocateCountryRecord struct {
	ContinentCode string `maxminddb:"continent_code"`
	CountryCode   string `maxminddb:"country_code"`
	CountryName   string `maxminddb:"country_name"`
}

type iplocateASNRecord struct {
	ASN         string `maxminddb:"asn"`
	CountryCode string `maxminddb:"country_code"`
	Name        string `maxminddb:"name"`
	Org         string `maxminddb:"org"`
	Domain      string `maxminddb:"domain"`
}

type maxMindCityRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// maxMindCountryRecord matches GeoLite2-Country / GeoIP2-Country (no city block).
type maxMindCountryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
}

type maxMindASNRecord struct {
	ASN    int64  `maxminddb:"autonomous_system_number"`
	ASNOrg string `maxminddb:"autonomous_system_organization"`
}

// Lookup returns enrichment data for the given IP. Missing fields stay zero.
func (d *DB) Lookup(ip netip.Addr) (Result, error) {
	var result Result

	if d == nil {
		return result, nil
	}

	lookupIP := ip
	if ip.Is4In6() {
		lookupIP = ip.Unmap()
	}

	if d.country != nil {
		switch d.countryLayout {
		case layoutIPLocateCountry:
			var rec iplocateCountryRecord

			if err := d.country.Lookup(lookupIP).Decode(&rec); err != nil {
				return result, fmt.Errorf("can't lookup IP-to-country: %w", err)
			}

			result.CountryCode = rec.CountryCode
			result.CountryName = rec.CountryName
			result.HasLocation = false
		case layoutMaxMindCity:
			var rec maxMindCityRecord

			if err := d.country.Lookup(lookupIP).Decode(&rec); err != nil {
				return result, fmt.Errorf("can't lookup city: %w", err)
			}

			result.CountryCode = rec.Country.ISOCode
			result.CountryName = rec.Country.Names["en"]

			if result.CountryCode == "" {
				result.CountryCode = rec.RegisteredCountry.ISOCode
			}

			if result.CountryName == "" {
				result.CountryName = rec.RegisteredCountry.Names["en"]
			}

			result.City = rec.City.Names["en"]

			if result.City == "" && len(rec.Subdivisions) > 0 {
				result.City = rec.Subdivisions[0].Names["en"]
			}

			result.Latitude = rec.Location.Latitude
			result.Longitude = rec.Location.Longitude
			result.HasLocation = result.CountryCode != "" || result.City != ""
		case layoutMaxMindCountry:
			var rec maxMindCountryRecord

			if err := d.country.Lookup(lookupIP).Decode(&rec); err != nil {
				return result, fmt.Errorf("can't lookup country: %w", err)
			}

			result.CountryCode = rec.Country.ISOCode
			result.CountryName = rec.Country.Names["en"]

			if result.CountryCode == "" {
				result.CountryCode = rec.RegisteredCountry.ISOCode
			}

			if result.CountryName == "" {
				result.CountryName = rec.RegisteredCountry.Names["en"]
			}

			result.HasLocation = false
		}
	}

	if d.asn != nil {
		switch d.asnLayout {
		case layoutIPLocateASN:
			var rec iplocateASNRecord

			if err := d.asn.Lookup(lookupIP).Decode(&rec); err != nil {
				return result, fmt.Errorf("can't lookup IP-to-ASN: %w", err)
			}

			asnNum, err := strconv.ParseInt(strings.TrimSpace(rec.ASN), 10, 64)
			if err != nil {
				asnNum = 0
			}

			result.ASN = asnNum

			switch {
			case rec.Org != "":
				result.ASNOrg = rec.Org
			case rec.Name != "":
				result.ASNOrg = rec.Name
			default:
				result.ASNOrg = rec.Domain
			}

			result.HasASN = result.ASN != 0 || result.ASNOrg != ""
		case layoutMaxMindASN:
			var rec maxMindASNRecord

			if err := d.asn.Lookup(lookupIP).Decode(&rec); err != nil {
				return result, fmt.Errorf("can't lookup ASN: %w", err)
			}

			result.ASN = rec.ASN
			result.ASNOrg = rec.ASNOrg
			result.HasASN = result.ASN != 0 || result.ASNOrg != ""
		}
	}

	return result, nil
}

// BuildCountryPrefixIndex walks the country/city MMDB and groups every IPv4
// network by its ISO-3166-1 alpha-2 country code. Returns nil when no country
// database is open, so callers can treat "country strategy unavailable" as a
// runtime concern rather than a startup failure.
func (d *DB) BuildCountryPrefixIndex() (*countryprefix.Index, error) {
	if d == nil || d.country == nil {
		return nil, nil
	}

	raw := make(map[string][]netip.Prefix, 256)

	for result := range d.country.Networks(maxminddb.SkipEmptyValues()) {
		prefix := result.Prefix()
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			continue
		}

		cc, err := decodeCountryCode(result, d.countryLayout)
		if err != nil {
			return nil, fmt.Errorf("can't decode country MMDB record at %s: %w", prefix, err)
		}

		if cc == "" {
			continue
		}

		raw[cc] = append(raw[cc], prefix)
	}

	return countryprefix.New(raw), nil
}

// decodeCountryCode pulls the ISO-3166-1 alpha-2 code out of one MMDB record
// using the layout detected at Open() time. Registered-country is consulted
// as a fallback so MaxMind records without a primary country attribution
// (anycast, satellite, etc.) still join the right bucket.
func decodeCountryCode(result maxminddb.Result, layout recordLayout) (string, error) {
	switch layout {
	case layoutIPLocateCountry:
		var rec iplocateCountryRecord

		if err := result.Decode(&rec); err != nil {
			return "", err
		}

		return strings.ToUpper(strings.TrimSpace(rec.CountryCode)), nil

	case layoutMaxMindCity:
		var rec maxMindCityRecord

		if err := result.Decode(&rec); err != nil {
			return "", err
		}

		cc := rec.Country.ISOCode
		if cc == "" {
			cc = rec.RegisteredCountry.ISOCode
		}

		return strings.ToUpper(strings.TrimSpace(cc)), nil

	case layoutMaxMindCountry:
		var rec maxMindCountryRecord

		if err := result.Decode(&rec); err != nil {
			return "", err
		}

		cc := rec.Country.ISOCode
		if cc == "" {
			cc = rec.RegisteredCountry.ISOCode
		}

		return strings.ToUpper(strings.TrimSpace(cc)), nil
	}

	return "", nil
}
