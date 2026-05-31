package dashboard

// RecentScan is one row of the recent-scans table.
type RecentScan struct {
	ScanID              uint64 `json:"scan_id"`
	Name                string `json:"name,omitempty"`
	Status              string `json:"status"`
	DurationSec         *int64 `json:"duration_sec,omitempty"`
	ServicesFound       uint64 `json:"services_found"`
	NewServices         int32  `json:"new_services"`
	DisappearedServices int32  `json:"disappeared_services"`
	ChangedServices     int32  `json:"changed_services"`
	FinishedAt          string `json:"finished_at,omitempty"`
}

// ScansResponse is the wire format of GET /v1/dashboard/scans/summary.
type ScansResponse struct {
	AvgDurationSec    *float64     `json:"avg_duration_sec,omitempty"`
	MedianDurationSec *float64     `json:"median_duration_sec,omitempty"`
	SuccessRate7d     *float64     `json:"success_rate_7d,omitempty"`
	Recent            []RecentScan `json:"recent"`
}
