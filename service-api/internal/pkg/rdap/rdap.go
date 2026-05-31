// Package rdap performs RDAP IP lookups via well-known regional registries.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// Config controls RDAP enrichment.
type Config struct {
	Enabled bool          `env:"RDAP_ENABLED" env-default:"false"`
	BaseURL string        `env:"RDAP_BASE_URL" env-default:"https://rdap.org"`
	Timeout time.Duration `env:"RDAP_TIMEOUT"  env-default:"10s"`
}

// Result captures the subset of RDAP IP network fields we persist.
type Result struct {
	NetworkName  string
	NetworkRange string
	Country      string
	Organization string
	AbuseEmail   string
	Source       string
	Raw          []byte
}

// Client performs RDAP queries.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// New builds a Client.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// LookupIP fetches the RDAP record for the supplied address.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (*Result, error) {
	if !c.cfg.Enabled {
		return nil, nil
	}

	url := c.cfg.BaseURL + "/ip/" + ip.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build rdap request: %w", err)
	}

	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "UltraViolet/0.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't perform rdap request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap returned %d", resp.StatusCode)
	}

	var payload rdapNetwork

	// 4 MB cap on the RDAP response body. Typical responses are < 10 KB;
	// the cap protects against a misbehaving aggregator that streams forever.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("can't decode rdap response: %w", err)
	}

	raw, _ := json.Marshal(payload)

	result := &Result{
		NetworkName:  payload.Name,
		NetworkRange: payload.HandleRange,
		Country:      payload.Country,
		Source:       c.cfg.BaseURL,
		Raw:          raw,
	}

	if payload.StartAddress != "" {
		result.NetworkRange = payload.StartAddress + " - " + payload.EndAddress
	}

	for _, entity := range payload.Entities {
		for _, role := range entity.Roles {
			switch role {
			case "abuse":
				result.AbuseEmail = vCardEmail(entity.VCardArray)
			case "registrant":
				result.Organization = vCardName(entity.VCardArray)
			}
		}
	}

	return result, nil
}

type rdapNetwork struct {
	Name         string       `json:"name"`
	HandleRange  string       `json:"handle"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Country      string       `json:"country"`
	Entities     []rdapEntity `json:"entities"`
	Status       []string     `json:"status"`
	Type         string       `json:"type"`
	IPVersion    string       `json:"ipVersion"`
	Events       []any        `json:"events"`
}

type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
}

// vCardEmail extracts the first email from a vCard array if present.
func vCardEmail(raw json.RawMessage) string {
	return vCardField(raw, "email")
}

// vCardName extracts the first organization name from a vCard array.
func vCardName(raw json.RawMessage) string {
	return vCardField(raw, "fn")
}

func vCardField(raw json.RawMessage, fieldName string) string {
	if len(raw) == 0 {
		return ""
	}

	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return ""
	}

	if len(arr) < 2 {
		return ""
	}

	entries, ok := arr[1].([]any)
	if !ok {
		return ""
	}

	for _, entry := range entries {
		row, ok := entry.([]any)
		if !ok || len(row) < 4 {
			continue
		}

		name, ok := row[0].(string)
		if !ok || name != fieldName {
			continue
		}

		value, ok := row[3].(string)
		if !ok {
			continue
		}

		return value
	}

	return ""
}
