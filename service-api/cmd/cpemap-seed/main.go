// cpemap-seed prints SQL INSERT statements for uv_cpe_product_map from the
// compiled-in productMap. Run once when authoring migration
// deploy/migrations/1_initial_schema.up.sql (after the uv_cpe_product_map index):
//
//	go run ./cmd/cpemap-seed >> deploy/migrations/1_initial_schema.up.sql
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cpemap"
)

func main() {
	rows := cpemap.BuiltinRows()

	for _, row := range rows {
		_, err := fmt.Fprintf(
			os.Stdout,
			"INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES (%s, %s, %s, 'builtin') ON CONFLICT DO NOTHING;\n",
			sqlString(row.ProductKey),
			sqlString(row.Vendor),
			sqlString(row.Product),
		)
		if err != nil {
			os.Exit(1)
		}
	}
}

func sqlString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
