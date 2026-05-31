package risk

import "strings"

// PortBucket classifies a port into one of the prior categories that
// uv_risk_protocol_prior keys on. The classification mirrors the legacy
// CASE expression in repositories/service so cutover does not change the
// exposure baseline for existing services.
type PortBucket string

const (
	// PortBucketDatabase covers mysql/postgres/mongo/redis/elasticsearch/couchdb.
	PortBucketDatabase PortBucket = "database"
	// PortBucketBrokerCache covers memcached/amqp/kafka/zookeeper.
	PortBucketBrokerCache PortBucket = "broker_cache"
	// PortBucketRemoteDesktop covers RDP/VNC.
	PortBucketRemoteDesktop PortBucket = "remote_desktop"
	// PortBucketPlaintext covers ftp/telnet/smtp/pop3/imap/snmp/ldap/mssql/oracle.
	PortBucketPlaintext PortBucket = "plaintext"
	// PortBucketHTTP covers HTTP ports (80/8080/8000/8081).
	PortBucketHTTP PortBucket = "http"
	// PortBucketHTTPS covers HTTPS ports (443/8443).
	PortBucketHTTPS PortBucket = "https"
	// PortBucketOther catches every port not classified above.
	PortBucketOther PortBucket = "other"
)

// ClassifyPort returns the PortBucket for a given port number. The mapping
// mirrors uv_service.risk_score CASE in 1_initial_schema.up.sql so v2 priors
// align with v1 buckets during cutover.
func ClassifyPort(port uint16) PortBucket {
	switch port {
	case 3306, 5432, 27017, 6379, 9200, 9300, 5984:
		return PortBucketDatabase
	case 11211, 5672, 9092, 2181:
		return PortBucketBrokerCache
	case 3389, 5900:
		return PortBucketRemoteDesktop
	case 21, 23, 25, 110, 143, 161, 162, 389, 1433, 1521:
		return PortBucketPlaintext
	case 80, 8080, 8000, 8081:
		return PortBucketHTTP
	case 443, 8443:
		return PortBucketHTTPS
	default:
		return PortBucketOther
	}
}

// ProtocolFamily groups protocols into coarse families used as the secondary
// key in uv_risk_protocol_prior. The "any" family is the universal fallback
// when no protocol-specific prior is configured.
type ProtocolFamily string

const (
	// ProtocolFamilyAny is the universal fallback used when no specific
	// protocol family matches the port bucket.
	ProtocolFamilyAny ProtocolFamily = "any"
	// ProtocolFamilyWeb covers HTTP/HTTPS-bearing protocols.
	ProtocolFamilyWeb ProtocolFamily = "web"
)

// ClassifyProtocol maps a probe-detected protocol string to a family used for
// prior lookup. Unknown protocols fall back to ProtocolFamilyAny.
func ClassifyProtocol(protocol string) ProtocolFamily {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "http", "https":
		return ProtocolFamilyWeb
	default:
		return ProtocolFamilyAny
	}
}

// PriorEntry is one row of uv_risk_protocol_prior loaded into memory.
type PriorEntry struct {
	PortBucket     PortBucket
	ProtocolFamily ProtocolFamily
	PExposure      float64
	PriorAlpha     float64
	PriorBeta      float64
}

// PriorTable is an in-memory lookup over (port_bucket, protocol_family) keys.
// Lookups fall back from the exact match to (port_bucket, any) before failing
// over to the global DefaultPriors() table.
type PriorTable struct {
	entries map[priorKey]PriorEntry
}

type priorKey struct {
	bucket PortBucket
	family ProtocolFamily
}

// NewPriorTable builds an immutable lookup table from the supplied rows.
func NewPriorTable(rows []PriorEntry) PriorTable {
	table := PriorTable{entries: make(map[priorKey]PriorEntry, len(rows))}

	for _, row := range rows {
		table.entries[priorKey{bucket: row.PortBucket, family: row.ProtocolFamily}] = row
	}

	return table
}

// PExposure resolves the baseline compromise probability for a service. The
// lookup order is (bucket, family) → (bucket, any) → seed fallback. The boolean
// return is true when a real row was matched (vs the seed default).
func (t PriorTable) PExposure(bucket PortBucket, family ProtocolFamily) (float64, bool) {
	if entry, ok := t.entries[priorKey{bucket: bucket, family: family}]; ok {
		return entry.PExposure, true
	}

	if entry, ok := t.entries[priorKey{bucket: bucket, family: ProtocolFamilyAny}]; ok {
		return entry.PExposure, true
	}

	return seedExposureFor(bucket), false
}
