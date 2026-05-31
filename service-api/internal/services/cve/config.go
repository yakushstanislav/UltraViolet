package cve

import "time"

// Config carries CVE API and sync bootstrap settings.
type Config struct {
	SyncBootstrapFrom time.Duration `env:"CVE_SYNC_BOOTSTRAP_FROM" env-default:"8760h"`
}
