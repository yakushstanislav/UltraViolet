// Package cverisk pulls vulnerability-prioritization signals from public
// feeds and exposes them as in-memory snapshots ready for batched DB upsert.
//
// Two sources are supported today:
//
//   - CISA KEV (Known Exploited Vulnerabilities): a hand-curated list of
//     CVEs CISA has confirmed are being exploited in the wild. Source:
//     https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//
//   - FIRST EPSS (Exploit Prediction Scoring System): daily-published per-CVE
//     probability that the vulnerability will be exploited in the next 30
//     days, plus the corresponding percentile. We use the gzipped CSV at
//     https://epss.cyentia.com/epss_scores-current.csv.gz so a single
//     request grabs every CVE in one go.
//
// Both clients are stateless; the calling worker owns persistence.
package cverisk

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Config controls the public-feed clients.
type Config struct {
	KEVURL    string        `env:"CVE_KEV_URL"   env-default:"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"`
	EPSSURL   string        `env:"CVE_EPSS_URL"  env-default:"https://epss.cyentia.com/epss_scores-current.csv.gz"`
	Timeout   time.Duration `env:"CVE_RISK_TIMEOUT" env-default:"60s"`
	UserAgent string        `env:"CVE_RISK_USER_AGENT" env-default:"UltraViolet/0.1"`
}

// KEVEntry is one row of the CISA KEV feed.
type KEVEntry struct {
	CVEID           string
	AddedAt         time.Time
	DueDate         time.Time
	KnownRansomware bool
}

// EPSSEntry is one row of the EPSS daily CSV.
type EPSSEntry struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// Client downloads KEV and EPSS feeds.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// New builds a Client.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: timeout},
	}
}

// FetchKEV downloads and parses the CISA KEV catalog. Returned entries are
// in feed order; CVE ids appear at most once. Network/parse errors are
// returned verbatim so the caller can decide retry policy.
func (c *Client) FetchKEV(ctx context.Context) ([]KEVEntry, error) {
	body, err := c.fetch(ctx, c.cfg.KEVURL, false)
	if err != nil {
		return nil, fmt.Errorf("can't fetch KEV catalog: %w", err)
	}

	var raw struct {
		Vulnerabilities []struct {
			CVEID           string `json:"cveID"`
			DateAdded       string `json:"dateAdded"`
			DueDate         string `json:"dueDate"`
			KnownRansomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("can't decode KEV catalog: %w", err)
	}

	out := make([]KEVEntry, 0, len(raw.Vulnerabilities))

	for _, v := range raw.Vulnerabilities {
		entry := KEVEntry{
			CVEID:           v.CVEID,
			KnownRansomware: v.KnownRansomware == "Known",
		}

		entry.AddedAt = parseKEVDate(v.DateAdded)
		entry.DueDate = parseKEVDate(v.DueDate)

		out = append(out, entry)
	}

	return out, nil
}

// FetchEPSS downloads and parses the EPSS daily CSV.
func (c *Client) FetchEPSS(ctx context.Context) ([]EPSSEntry, error) {
	body, err := c.fetch(ctx, c.cfg.EPSSURL, true)
	if err != nil {
		return nil, fmt.Errorf("can't fetch EPSS feed: %w", err)
	}

	reader := csv.NewReader(byteReader(body))
	reader.FieldsPerRecord = -1

	out := make([]EPSSEntry, 0, 200_000)

	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("can't read EPSS row: %w", err)
		}

		if len(row) < 3 {
			continue
		}

		if row[0] == "" || row[0] == "cve" || row[0][0] == '#' {
			continue
		}

		score, err := strconv.ParseFloat(row[1], 64)
		if err != nil {
			continue
		}

		percentile, err := strconv.ParseFloat(row[2], 64)
		if err != nil {
			continue
		}

		out = append(out, EPSSEntry{
			CVEID:      row[0],
			Score:      score,
			Percentile: percentile,
		})
	}

	return out, nil
}

func (c *Client) fetch(ctx context.Context, url string, gzipped bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build request: %w", err)
	}

	req.Header.Set("User-Agent", c.cfg.UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body

	if gzipped {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("can't open gzip stream: %w", err)
		}

		defer func() { _ = gz.Close() }()

		reader = gz
	}

	// CISA's KEV JSON is ~1 MB; FIRST.org EPSS gzipped CSV is ~30 MB and
	// decompresses to ~150 MB. 256 MB cap is generous headroom but still
	// bounds memory if a feed misbehaves or is replaced with a payload bomb.
	return io.ReadAll(io.LimitReader(reader, maxFeedBytes))
}

const maxFeedBytes = 256 * 1024 * 1024

func parseKEVDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	for _, layout := range []string{"2006-01-02", time.RFC3339, time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}

	return time.Time{}
}

type sliceReader struct {
	data []byte
	pos  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	n := copy(p, r.data[r.pos:])
	r.pos += n

	return n, nil
}

func byteReader(b []byte) io.Reader { return &sliceReader{data: b} }
