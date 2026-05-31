// Package countryprefix maps ISO-3166-1 alpha-2 country codes to the IPv4
// prefixes that a GeoIP MMDB attributes to each country. The index is built
// once from the country/city MMDB owned by internal/pkg/geoip and queried by
// the scanner whenever a target_strategy=country scan runs.
package countryprefix

import (
	"net/netip"
	"sort"
	"strings"
)

// Index holds the country-code → IPv4 prefixes mapping.
type Index struct {
	byCC map[string][]netip.Prefix
}

// New builds an Index from a map of ISO-3166-1 alpha-2 codes to IPv4 prefix
// slices. Keys are normalised to upper case; non-IPv4 prefixes are dropped;
// empty keys are skipped.
func New(raw map[string][]netip.Prefix) *Index {
	byCC := make(map[string][]netip.Prefix, len(raw))

	for cc, prefixes := range raw {
		cc = strings.TrimSpace(strings.ToUpper(cc))
		if cc == "" {
			continue
		}

		filtered := make([]netip.Prefix, 0, len(prefixes))

		for _, prefix := range prefixes {
			if !prefix.IsValid() {
				continue
			}

			if !prefix.Addr().Is4() {
				continue
			}

			filtered = append(filtered, prefix)
		}

		if len(filtered) == 0 {
			continue
		}

		byCC[cc] = append(byCC[cc], filtered...)
	}

	return &Index{byCC: byCC}
}

// Prefixes returns the IPv4 prefixes for the given country code, or nil if
// the index has no records for that country. The lookup is case-insensitive.
// The returned slice is a fresh copy; the caller may mutate it freely.
func (i *Index) Prefixes(cc string) []netip.Prefix {
	if i == nil {
		return nil
	}

	prefixes, ok := i.byCC[strings.ToUpper(strings.TrimSpace(cc))]
	if !ok {
		return nil
	}

	out := make([]netip.Prefix, len(prefixes))
	copy(out, prefixes)

	return out
}

// Countries returns the alphabetically sorted list of country codes the
// index has at least one IPv4 prefix for.
func (i *Index) Countries() []string {
	if i == nil {
		return nil
	}

	out := make([]string, 0, len(i.byCC))
	for cc := range i.byCC {
		out = append(out, cc)
	}

	sort.Strings(out)

	return out
}

// Len reports the number of countries with at least one IPv4 prefix.
func (i *Index) Len() int {
	if i == nil {
		return 0
	}

	return len(i.byCC)
}

// PrefixCount reports the total number of IPv4 prefixes across all countries.
func (i *Index) PrefixCount() int {
	if i == nil {
		return 0
	}

	total := 0
	for _, prefixes := range i.byCC {
		total += len(prefixes)
	}

	return total
}
