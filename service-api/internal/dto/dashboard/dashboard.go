package dashboard

// Response is the wire format of GET /v1/dashboard.
type Response struct {
	Hosts    uint64 `json:"hosts"`
	Services uint64 `json:"services"`
	Pending  uint64 `json:"pending"`
	Running  uint64 `json:"running"`
	Paused   uint64 `json:"paused"`
	Done     uint64 `json:"done"`
	Failed   uint64 `json:"failed"`

	Scans24h           uint64 `json:"scans_24h"`
	Scans7d            uint64 `json:"scans_7d"`
	Scans30d           uint64 `json:"scans_30d"`
	LastScanFinishedAt string `json:"last_scan_finished_at,omitempty"`

	AlertsActive   uint64 `json:"alerts_active"`
	AlertsFired24h uint64 `json:"alerts_fired_24h"`

	SavedSearches uint64 `json:"saved_searches"`

	ChangeEvents7dNew         uint64 `json:"change_events_7d_new"`
	ChangeEvents7dDisappeared uint64 `json:"change_events_7d_disappeared"`
	ChangeEvents7dChanged     uint64 `json:"change_events_7d_changed"`

	HostsWithCriticalCVE uint64   `json:"hosts_with_critical_cve"`
	CVECritical          uint64   `json:"cve_critical"`
	CVEHigh              uint64   `json:"cve_high"`
	CVEMedium            uint64   `json:"cve_medium"`
	CVELow               uint64   `json:"cve_low"`
	TopCVEs              []TopCVE `json:"top_cves,omitempty"`
}

// TopCVE is one row in the dashboard "top CVEs" list.
type TopCVE struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity,omitempty"`
	Score    *float64 `json:"cvss_score,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Services uint64   `json:"services"`
}
