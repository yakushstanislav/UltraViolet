package cpemap

import "sort"

// ProductMapRow is one (product_key → vendor, product) row for uv_cpe_product_map.
type ProductMapRow struct {
	ProductKey string
	Vendor     string
	Product    string
}

// BuiltinRows returns every row from the compiled-in productMap, sorted for
// stable seed generation (cmd/cpemap-seed).
func BuiltinRows() []ProductMapRow {
	rows := make([]ProductMapRow, 0, len(productMap)*2)

	for key, coords := range productMap {
		for _, coord := range coords {
			rows = append(rows, ProductMapRow{
				ProductKey: key,
				Vendor:     coord.Vendor,
				Product:    coord.Product,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ProductKey != rows[j].ProductKey {
			return rows[i].ProductKey < rows[j].ProductKey
		}

		if rows[i].Vendor != rows[j].Vendor {
			return rows[i].Vendor < rows[j].Vendor
		}

		return rows[i].Product < rows[j].Product
	})

	return rows
}

// BuiltinMap returns a copy of the compiled-in product map for offline use.
func BuiltinMap() map[string][]Coord {
	out := make(map[string][]Coord, len(productMap))

	for key, coords := range productMap {
		cp := make([]Coord, len(coords))
		copy(cp, coords)

		out[key] = cp
	}

	return out
}
