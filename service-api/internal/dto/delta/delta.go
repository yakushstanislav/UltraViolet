package delta

// SummaryResponse is the JSON wire format for GET /v1/scans/{id}/delta.
type SummaryResponse struct {
	ScanID              uint64  `json:"scan_id"`
	PreviousScanID      *uint64 `json:"previous_scan_id"`
	NewServices         int32   `json:"new_services"`
	DisappearedServices int32   `json:"disappeared_services"`
	ChangedServices     int32   `json:"changed_services"`
	CreatedAt           string  `json:"created_at"`
}
