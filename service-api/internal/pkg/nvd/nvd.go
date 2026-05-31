// Package nvd is a minimal client for the NVD CVE 2.0 REST API.
//
// Reference: https://nvd.nist.gov/developers/vulnerabilities
//
// The client paginates over /rest/json/cves/2.0 and yields decoded vulnerability
// entries. It applies the NIST-recommended request throttle so callers don't
// trip the public rate limit:
//
//   - without API key: 5 requests per 30 seconds rolling window;
//   - with API key:    50 requests per 30 seconds rolling window.
//
// The throttle is implemented as a fixed sleep between successive requests
// to keep the implementation dependency-free.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Config controls the NVD client.
type Config struct {
	Enabled     bool          `env:"CVE_SYNC_ENABLED" env-default:"true"`
	BaseURL     string        `env:"NVD_BASE_URL"     env-default:"https://services.nvd.nist.gov"`
	APIKey      string        `env:"NVD_API_KEY"      env-default:""`
	Timeout     time.Duration `env:"NVD_TIMEOUT"      env-default:"30s"`
	PageSize    int           `env:"NVD_PAGE_SIZE"    env-default:"2000"`
	UserAgent   string        `env:"NVD_USER_AGENT"   env-default:"UltraViolet/0.1"`
	MaxRetries  int           `env:"NVD_MAX_RETRIES"  env-default:"5"`
	MinInterval time.Duration `env:"NVD_MIN_INTERVAL" env-default:"0s"`
}

// Client is a thin NVD CVE 2.0 client.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// New builds a Client.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if cfg.PageSize <= 0 || cfg.PageSize > 2000 {
		cfg.PageSize = 2000
	}

	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}

	if cfg.MinInterval <= 0 {
		// NIST guidance: 5 req/30s ≈ 6s gap unauthenticated; 50 req/30s ≈ 0.6s with key.
		if cfg.APIKey == "" {
			cfg.MinInterval = 6500 * time.Millisecond
		} else {
			cfg.MinInterval = 700 * time.Millisecond
		}
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://services.nvd.nist.gov"
	}

	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: timeout},
	}
}

// Query selects which CVEs to fetch.
type Query struct {
	// LastModStart, when non-zero, fetches CVEs modified on or after this
	// instant. The companion LastModEnd is required by NVD and is filled in
	// automatically (set to time.Now() if zero).
	LastModStart time.Time
	LastModEnd   time.Time
}

// Vulnerability is a flat, ingest-friendly view of one CVE entry.
type Vulnerability struct {
	ID              string
	Summary         string
	PublishedAt     time.Time
	LastModifiedAt  time.Time
	CVSSv3Score     float64
	CVSSv3Severity  string
	CVSSv3Vector    string
	CVSSv31Score    float64
	CVSSv31Severity string
	CVSSv31Vector   string
	CVSSv40Score    float64
	CVSSv40Severity string
	CVSSv40Vector   string
	References      []string
	CPELeaves       []CPELeaf
	Raw             json.RawMessage
}

// CPELeaf is a single applicability statement flattened out of the (possibly
// nested) NVD `configurations` tree.
//
// TargetSW / TargetHW / Negate are filled when the catalog specifies them so
// downstream matching can drop leaves that explicitly don't apply (e.g.
// "PostgreSQL JDBC driver" leaves on a service we know is a PostgreSQL
// server, or "negate" inversions).
type CPELeaf struct {
	Vulnerable            bool
	Criteria              string
	Vendor                string
	Product               string
	ExactVersion          string
	VersionStartIncluding string
	VersionStartExcluding string
	VersionEndIncluding   string
	VersionEndExcluding   string
	TargetSW              string
	TargetHW              string
	Negate                bool
}

// Page is one chunk yielded by Iterate.
type Page struct {
	TotalResults    int
	ResultsPerPage  int
	StartIndex      int
	Vulnerabilities []Vulnerability
}

// TotalCount fetches the catalog-wide CVE count without iterating; it issues
// one request with resultsPerPage=1 so the response is tiny. Used by cvesync
// to populate uv_cve_sync_state.entries_total for the dashboard progress bar.
func (c *Client) TotalCount(ctx context.Context) (int, error) {
	values := url.Values{}
	values.Set("resultsPerPage", "1")
	values.Set("startIndex", "0")

	endpoint := c.cfg.BaseURL + "/rest/json/cves/2.0?" + values.Encode()

	body, err := c.do(ctx, endpoint)
	if err != nil {
		return 0, err
	}

	var raw rawResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return 0, fmt.Errorf("can't decode nvd total response: %w", err)
	}

	return raw.TotalResults, nil
}

// Iterate fetches all pages matching q and invokes fn for each page in order.
// Throttling and retries are applied internally; if fn returns an error the
// iteration stops and that error is returned.
func (c *Client) Iterate(ctx context.Context, q Query, fn func(context.Context, Page) error) error {
	if !c.cfg.Enabled {
		return nil
	}

	startIndex := 0

	for {
		page, err := c.fetchPage(ctx, q, startIndex)
		if err != nil {
			return err
		}

		if err := fn(ctx, page); err != nil {
			return err
		}

		startIndex += page.ResultsPerPage
		if startIndex >= page.TotalResults || len(page.Vulnerabilities) == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.cfg.MinInterval):
		}
	}
}

func (c *Client) fetchPage(ctx context.Context, q Query, startIndex int) (Page, error) {
	values := url.Values{}
	values.Set("resultsPerPage", strconv.Itoa(c.cfg.PageSize))
	values.Set("startIndex", strconv.Itoa(startIndex))

	if !q.LastModStart.IsZero() {
		end := q.LastModEnd
		if end.IsZero() {
			end = time.Now().UTC()
		}

		// NVD requires both bounds when filtering by last-modified date and
		// rejects ranges longer than 120 days. Callers should clamp upstream.
		values.Set("lastModStartDate", q.LastModStart.UTC().Format(time.RFC3339))
		values.Set("lastModEndDate", end.UTC().Format(time.RFC3339))
	}

	endpoint := c.cfg.BaseURL + "/rest/json/cves/2.0?" + values.Encode()

	body, err := c.do(ctx, endpoint)
	if err != nil {
		return Page{}, err
	}

	var raw rawResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return Page{}, fmt.Errorf("can't decode nvd response: %w", err)
	}

	page := Page{
		TotalResults:    raw.TotalResults,
		ResultsPerPage:  raw.ResultsPerPage,
		StartIndex:      raw.StartIndex,
		Vulnerabilities: make([]Vulnerability, 0, len(raw.Vulnerabilities)),
	}

	for _, item := range raw.Vulnerabilities {
		entry := flattenCVE(item.CVE)
		page.Vulnerabilities = append(page.Vulnerabilities, entry)
	}

	return page, nil
}

func (c *Client) do(ctx context.Context, endpoint string) ([]byte, error) {
	var lastErr error

	for attempt := range c.cfg.MaxRetries {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("can't build nvd request: %w", err)
		}

		req.Header.Set("User-Agent", c.cfg.UserAgent)
		req.Header.Set("Accept", "application/json")

		if c.cfg.APIKey != "" {
			req.Header.Set("apiKey", c.cfg.APIKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("can't perform nvd request: %w", err)

			if !sleepFor(ctx, backoffForAttempt(attempt)) {
				return nil, ctx.Err()
			}

			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()

		if readErr != nil {
			lastErr = fmt.Errorf("can't read nvd response: %w", readErr)

			if !sleepFor(ctx, backoffForAttempt(attempt)) {
				return nil, ctx.Err()
			}

			continue
		}

		switch {
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("nvd returned %d: %s", resp.StatusCode, snippet(body))

			wait := retryAfterDelay(resp.Header, backoffForAttempt(attempt))
			if !sleepFor(ctx, wait) {
				return nil, ctx.Err()
			}

			continue
		default:
			return nil, fmt.Errorf("nvd returned %d: %s", resp.StatusCode, snippet(body))
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("nvd: exhausted retries")
}

// maxResponseBytes caps every NVD page we read into memory. NVD's largest
// 2000-item windows clock in around 6-8 MB; 32 MB gives generous headroom
// while still bounding worst-case memory on a buggy or malicious response.
const maxResponseBytes = 32 * 1024 * 1024

func backoffForAttempt(attempt int) time.Duration {
	base := time.Duration(1<<attempt) * time.Second
	if base > 30*time.Second {
		base = 30 * time.Second
	}

	// Jitter ±25% so concurrent workers retrying after a shared NVD blip
	// don't synchronise on the same millisecond. The bound stays below
	// 1.25 * 30 s = 37.5 s in the worst case.
	// math/rand is fine here: jitter is for desynchronising worker retries,
	// not a security boundary.
	jitter := time.Duration(rand.Int64N(int64(base / 2))) //nolint:gosec // jitter only, not a security primitive
	jitter -= base / 4

	return base + jitter
}

// retryAfterDelay honours the server's Retry-After header (seconds or HTTP
// date format) and falls back to fallback when the header is absent or
// malformed.
func retryAfterDelay(h http.Header, fallback time.Duration) time.Duration {
	raw := h.Get("Retry-After")
	if raw == "" {
		return fallback
	}

	if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}

	if t, err := http.ParseTime(raw); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}

	return fallback
}

func sleepFor(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}

	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func snippet(body []byte) string {
	const limit = 240
	if len(body) > limit {
		return string(body[:limit]) + "…"
	}

	return string(body)
}

func flattenCVE(c rawCVE) Vulnerability {
	out := Vulnerability{
		ID:             c.ID,
		Summary:        firstEnglishDescription(c.Descriptions),
		PublishedAt:    parseTime(c.Published),
		LastModifiedAt: parseTime(c.LastModified),
	}

	if score, severity, vector, ok := pickCVSSv3(c.Metrics); ok {
		out.CVSSv3Score = score
		out.CVSSv3Severity = severity
		out.CVSSv3Vector = vector
	}

	if score, severity, vector, ok := pickCVSSv31(c.Metrics); ok {
		out.CVSSv31Score = score
		out.CVSSv31Severity = severity
		out.CVSSv31Vector = vector
	}

	if score, severity, vector, ok := pickCVSSv40(c.Metrics); ok {
		out.CVSSv40Score = score
		out.CVSSv40Severity = severity
		out.CVSSv40Vector = vector
	}

	for _, ref := range c.References {
		if ref.URL != "" {
			out.References = append(out.References, ref.URL)
		}
	}

	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			out.CPELeaves = append(out.CPELeaves, walkNode(node)...)
		}
	}

	if rawBytes, err := json.Marshal(c); err == nil {
		out.Raw = rawBytes
	}

	return out
}

func walkNode(node rawNode) []CPELeaf {
	leaves := make([]CPELeaf, 0, len(node.CPEMatch))

	for _, match := range node.CPEMatch {
		leaf := CPELeaf{
			Vulnerable:            match.Vulnerable,
			Criteria:              match.Criteria,
			VersionStartIncluding: match.VersionStartIncluding,
			VersionStartExcluding: match.VersionStartExcluding,
			VersionEndIncluding:   match.VersionEndIncluding,
			VersionEndExcluding:   match.VersionEndExcluding,
			Negate:                node.Negate,
		}

		fields := parseCPECriteria(match.Criteria)
		leaf.Vendor = fields.Vendor
		leaf.Product = fields.Product
		leaf.ExactVersion = fields.Version
		leaf.TargetSW = fields.TargetSW
		leaf.TargetHW = fields.TargetHW

		leaves = append(leaves, leaf)
	}

	for _, child := range node.Children {
		leaves = append(leaves, walkNode(child)...)
	}

	return leaves
}

// cpeFields holds the parsed CPE 2.3 components we care about.
type cpeFields struct {
	Vendor   string
	Product  string
	Version  string
	TargetSW string
	TargetHW string
}

// parseCPECriteria parses a CPE 2.3 URI. The format is
// `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`.
// Wildcards (`*`, `-`) collapse to empty strings.
func parseCPECriteria(criteria string) cpeFields {
	if criteria == "" {
		return cpeFields{}
	}

	const minParts = 6

	parts := splitCPE(criteria)
	if len(parts) < minParts {
		return cpeFields{}
	}

	out := cpeFields{
		Vendor:  parts[3],
		Product: parts[4],
		Version: cpeWildcardToEmpty(parts[5]),
	}

	if len(parts) > 10 {
		out.TargetSW = cpeWildcardToEmpty(parts[10])
	}

	if len(parts) > 11 {
		out.TargetHW = cpeWildcardToEmpty(parts[11])
	}

	return out
}

func cpeWildcardToEmpty(v string) string {
	if v == "*" || v == "-" {
		return ""
	}

	return v
}

// splitCPE tolerates the (rare) escaped colons in CPE 2.3 strings.
func splitCPE(s string) []string {
	out := make([]string, 0, 13)
	buf := make([]byte, 0, len(s))

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			buf = append(buf, s[i+1])

			i++

			continue
		}

		if ch == ':' {
			out = append(out, string(buf))
			buf = buf[:0]

			continue
		}

		buf = append(buf, ch)
	}

	out = append(out, string(buf))

	return out
}

func firstEnglishDescription(items []rawLangText) string {
	for _, item := range items {
		if item.Lang == "en" {
			return item.Value
		}
	}

	if len(items) > 0 {
		return items[0].Value
	}

	return ""
}

func pickCVSSv3(metrics rawMetrics) (score float64, severity, vector string, ok bool) {
	if len(metrics.CVSSv31) > 0 {
		entry := metrics.CVSSv31[0]

		return entry.CVSSData.BaseScore, entry.CVSSData.BaseSeverity, entry.CVSSData.VectorString, true
	}

	if len(metrics.CVSSv30) > 0 {
		entry := metrics.CVSSv30[0]

		return entry.CVSSData.BaseScore, entry.CVSSData.BaseSeverity, entry.CVSSData.VectorString, true
	}

	return 0, "", "", false
}

func pickCVSSv31(metrics rawMetrics) (score float64, severity, vector string, ok bool) {
	if len(metrics.CVSSv31) == 0 {
		return 0, "", "", false
	}

	entry := metrics.CVSSv31[0]

	return entry.CVSSData.BaseScore, entry.CVSSData.BaseSeverity, entry.CVSSData.VectorString, true
}

func pickCVSSv40(metrics rawMetrics) (score float64, severity, vector string, ok bool) {
	if len(metrics.CVSSv40) == 0 {
		return 0, "", "", false
	}

	entry := metrics.CVSSv40[0]

	return entry.CVSSData.BaseScore, entry.CVSSData.BaseSeverity, entry.CVSSData.VectorString, true
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}

	return time.Time{}
}

type rawResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []rawVulnerability `json:"vulnerabilities"`
}

type rawVulnerability struct {
	CVE rawCVE `json:"cve"`
}

type rawCVE struct {
	ID             string             `json:"id"`
	Published      string             `json:"published"`
	LastModified   string             `json:"lastModified"`
	Descriptions   []rawLangText      `json:"descriptions"`
	Metrics        rawMetrics         `json:"metrics"`
	References     []rawReference     `json:"references"`
	Configurations []rawConfiguration `json:"configurations"`
}

type rawLangText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type rawReference struct {
	URL string `json:"url"`
}

type rawMetrics struct {
	CVSSv31 []rawCVSSEntry `json:"cvssMetricV31"`
	CVSSv30 []rawCVSSEntry `json:"cvssMetricV30"`
	CVSSv40 []rawCVSSEntry `json:"cvssMetricV40"`
}

type rawCVSSEntry struct {
	CVSSData rawCVSSData `json:"cvssData"`
}

type rawCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type rawConfiguration struct {
	Nodes []rawNode `json:"nodes"`
}

type rawNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CPEMatch []rawCPEMatch `json:"cpeMatch"`
	Children []rawNode     `json:"children"`
}

type rawCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}
