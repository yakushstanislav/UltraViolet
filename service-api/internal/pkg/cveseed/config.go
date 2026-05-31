package cveseed

// Config selects optional CVE catalog seed sources applied after migrations.
type Config struct {
	SeedFile string `env:"CVE_CATALOG_SEED_FILE"`
	SeedDir  string `env:"CVE_CATALOG_SEED_DIR"`
}
