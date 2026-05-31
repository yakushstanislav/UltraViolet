// Package forwarddns performs bulk forward DNS lookups for a set of
// hostnames. Queries are issued through github.com/miekg/dns against a
// configurable resolver pool with retries and round-robin failover, so the
// scanner doesn't depend on the host's /etc/resolv.conf.
package forwarddns

import "time"

// Config controls optional forward DNS enrichment after a PTR pass.
type Config struct {
	Enabled bool `env:"FDNS_ENABLED" env-default:"true"`
	Threads int  `env:"FDNS_THREADS" env-default:"8"`
	// Timeout caps the entire batch — once exceeded, in-flight queries are
	// abandoned and partially-collected records are returned to the caller.
	Timeout time.Duration `env:"FDNS_TIMEOUT" env-default:"2m"`
	// Resolvers is the round-robin pool of upstream resolvers as host:port.
	// Defaults to public anycast resolvers; override with a comma-separated
	// list to use an internal DNS.
	Resolvers []string `env:"FDNS_RESOLVERS" env-default:"1.1.1.1:53,8.8.8.8:53" env-separator:","`
	// PerQueryTimeout is the deadline applied to a single resolver call.
	PerQueryTimeout time.Duration `env:"FDNS_QUERY_TIMEOUT" env-default:"3s"`
	// Retries is the number of additional attempts (on other resolvers) when
	// a query fails with a transient error or times out. 0 = no retries.
	Retries int `env:"FDNS_RETRIES" env-default:"1"`
	// CacheTTL bounds the in-process answer cache used within a single batch,
	// so a zone's NS/SOA isn't re-queried for every subdomain and repeated
	// names resolve once. The effective TTL is min(CacheTTL, answer RR TTL).
	// 0 = off.
	CacheTTL time.Duration `env:"FDNS_CACHE_TTL" env-default:"5m"`
}
