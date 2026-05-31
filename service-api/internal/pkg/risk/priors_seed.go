package risk

// DefaultPriors returns the seed PriorTable compiled into the binary. The
// values must stay in lockstep with the rows inserted by migration
// 5_risk_v2_foundation.up.sql so a fresh database and a fresh binary agree
// before the operator customises any rows.
func DefaultPriors() PriorTable {
	return NewPriorTable([]PriorEntry{
		{PortBucket: PortBucketDatabase, ProtocolFamily: ProtocolFamilyAny, PExposure: 0.50, PriorAlpha: 1, PriorBeta: 1},
		{PortBucket: PortBucketBrokerCache, ProtocolFamily: ProtocolFamilyAny, PExposure: 0.40, PriorAlpha: 1, PriorBeta: 1},
		{PortBucket: PortBucketRemoteDesktop, ProtocolFamily: ProtocolFamilyAny, PExposure: 0.45, PriorAlpha: 1, PriorBeta: 1},
		{PortBucket: PortBucketPlaintext, ProtocolFamily: ProtocolFamilyAny, PExposure: 0.35, PriorAlpha: 1, PriorBeta: 1},
		{PortBucket: PortBucketHTTP, ProtocolFamily: ProtocolFamilyWeb, PExposure: 0.05, PriorAlpha: 1, PriorBeta: 1},
		{PortBucket: PortBucketHTTPS, ProtocolFamily: ProtocolFamilyWeb, PExposure: 0.05, PriorAlpha: 1, PriorBeta: 1},
		{PortBucket: PortBucketOther, ProtocolFamily: ProtocolFamilyAny, PExposure: 0.10, PriorAlpha: 1, PriorBeta: 1},
	})
}

// seedExposureFor is the last-resort exposure baseline used when neither a
// configured row nor a seeded family-any row matches.
func seedExposureFor(bucket PortBucket) float64 {
	switch bucket {
	case PortBucketDatabase:
		return 0.50
	case PortBucketBrokerCache:
		return 0.40
	case PortBucketRemoteDesktop:
		return 0.45
	case PortBucketPlaintext:
		return 0.35
	case PortBucketHTTP, PortBucketHTTPS:
		return 0.05
	default:
		return 0.10
	}
}
