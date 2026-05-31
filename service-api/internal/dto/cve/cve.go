// Package cve carries the wire-level shapes for CVE-related endpoints.
package cve

// ServiceCVE is one CVE attached to a service, used by both /services/{id}/cves
// and the embedded host page payload.
type ServiceCVE struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity,omitempty"`
	CVSSScore      *float64 `json:"cvss_score,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	MatchedVersion string   `json:"matched_version,omitempty"`
	MatchedAt      string   `json:"matched_at"`
	Confidence     *int     `json:"confidence,omitempty"`
}

// SyncStatus is returned by GET /v1/cve/sync-status.
//
// EntriesDone / EntriesTotal are the real CVE counts mirrored locally vs. the
// catalog-wide total reported by NVD (refreshed at most once per hour). They
// are nullable: until cvesync has populated entries_total at least once, only
// the time-window fallback is meaningful.
type SyncStatus struct {
	Bootstrapped bool     `json:"bootstrapped"`
	Progress     *float64 `json:"progress,omitempty"`
	EntriesDone  *int     `json:"entries_done,omitempty"`
	EntriesTotal *int     `json:"entries_total,omitempty"`
}

// CVE is the wire-level representation of an NVD catalog entry.
type CVE struct {
	ID             string   `json:"id"`
	Source         string   `json:"source,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	CVSSScore      *float64 `json:"cvss_score,omitempty"`
	CVSSSeverity   string   `json:"cvss_severity,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	References     []string `json:"references,omitempty"`
	PublishedAt    string   `json:"published_at,omitempty"`
	LastModifiedAt string   `json:"last_modified_at,omitempty"`
}
