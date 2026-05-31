// Package reversedns performs bulk PTR lookups using Go's net.Resolver.
package reversedns

import "time"

// Config controls optional PTR batching after a scan.
//
// Timeout bounds the whole batch; PerLookupTimeout caps a single lookup so a
// slow / hostile upstream resolver can't starve every concurrent worker by
// keeping a single lookup in flight for the batch's full budget.
//
// When Resolvers is non-empty, PTR goes through the same miekg/dns resolver
// pool (with retries and round-robin failover) as the forward DNS pass, so
// reverse DNS no longer depends on the container's /etc/resolv.conf. Leave
// Resolvers blank to keep the legacy net.DefaultResolver behaviour for closed
// networks that must use the system resolver.
type Config struct {
	Enabled          bool          `env:"RDNS_PTR_ENABLED"        env-default:"true"`
	Threads          int           `env:"RDNS_GO_PROCESSES"       env-default:"8"`
	Timeout          time.Duration `env:"RDNS_TIMEOUT"            env-default:"2m"`
	PerLookupTimeout time.Duration `env:"RDNS_PER_LOOKUP_TIMEOUT" env-default:"5s"`
	// Resolvers is the round-robin pool as host:port. Empty = system resolver.
	Resolvers []string `env:"RDNS_RESOLVERS" env-default:"1.1.1.1:53,8.8.8.8:53" env-separator:","`
	// Retries is the number of additional attempts (on other resolvers) for a
	// transient failure. Only used when Resolvers is set.
	Retries int `env:"RDNS_RETRIES" env-default:"1"`
	// CacheTTL bounds the in-process PTR answer cache. 0 = off. Only used when
	// Resolvers is set.
	CacheTTL time.Duration `env:"RDNS_CACHE_TTL" env-default:"5m"`
}
