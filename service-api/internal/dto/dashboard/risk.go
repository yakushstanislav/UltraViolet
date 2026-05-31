package dashboard

// ScoreBucket is one row of the risk-score histogram.
type ScoreBucket struct {
	Bucket string `json:"bucket"`
	Count  uint64 `json:"count"`
}

// RiskyService is one row of the top-risky-services list.
type RiskyService struct {
	ServiceID uint64 `json:"service_id"`
	HostIP    string `json:"host_ip"`
	Port      uint16 `json:"port"`
	Protocol  string `json:"protocol,omitempty"`
	RiskScore int32  `json:"risk_score"`
	TopFactor string `json:"top_factor,omitempty"`
}

// RiskyHost is one row of the top-risky-hosts list.
type RiskyHost struct {
	HostID                uint64 `json:"host_id"`
	IP                    string `json:"ip"`
	CountryCode           string `json:"country_code,omitempty"`
	HighRiskServicesCount uint64 `json:"high_risk_services_count,omitempty"`
	RiskScore             int32  `json:"risk_score"`
	TopFactor             string `json:"top_factor,omitempty"`
}

// RiskResponse is the wire format of GET /v1/dashboard/risk.
type RiskResponse struct {
	ScoreBuckets     []ScoreBucket  `json:"score_buckets"`
	HostScoreBuckets []ScoreBucket  `json:"host_score_buckets"`
	TopRiskyServices []RiskyService `json:"top_risky_services"`
	TopRiskyHosts    []RiskyHost    `json:"top_risky_hosts"`
}
