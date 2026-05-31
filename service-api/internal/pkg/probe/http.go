package probe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// isPrivateHost reports whether host (a hostname or IP literal) resolves to
// an obviously non-routable address: loopback, link-local, RFC1918, ULA, or
// the IPv6 unspecified range. Hostnames are not resolved here — only literal
// IPs are inspected, since the probe is following a server-supplied redirect
// and we can't (cheaply) trust DNS to give the same answer twice.
func isPrivateHost(host string) bool {
	if host == "" {
		return false
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	return addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsPrivate() ||
		addr.IsUnspecified()
}

var titleRegexp = regexp.MustCompile(`(?is)<title[^>]*>([^<]*)</title>`)

func init() {
	// 80 / 8080 / 8000 — generic HTTP and Tomcat/Jetty/PHP-FPM frontends.
	// The extra ports cover popular admin/observability stacks that listen
	// on plain HTTP by default. Each one feeds the fingerprinter a Server:
	// header or a body that already contains the product version, which
	// downstream cvematch turns into CVE associations:
	//   3000  — Grafana / Gitea / Gogs / Node.js apps
	//   5000  — Flask debug / Docker Registry / generic Python WSGI
	//   8086  — InfluxDB (X-Influxdb-Version: 1.8.10)
	//   8123  — ClickHouse HTTP (X-ClickHouse-Server-Display-Name)
	//   8200  — HashiCorp Vault (X-Vault-Server)
	//   8500  — HashiCorp Consul (X-Consul-* headers, /v1/agent/self)
	//   5984  — Apache CouchDB ({"couchdb":"Welcome","version":"3.x.y"})
	//   9090  — Prometheus / Cockpit / SAP Management Console
	//   9091  — Prometheus pushgateway / Transmission
	//   15672 — RabbitMQ management plugin (/api/overview → rabbitmq_version)
	//   8888 / 9000 / 9999 — alternate HTTP admin ports (random scans hit these
	//   constantly with empty banners when the generic banner probe ran first).
	//   81    — alt HTTP commonly used by CCTV NVR/DVR web UIs and SOHO routers
	//   5800  — VNC HTTP gateway (RealVNC / TightVNC / UltraVNC web client)
	//   7070  — Real-Time Streaming admin / Cisco AnyConnect web portal
	//   16080 — Akamai accelerated HTTP edge
	//   8081 / 8082 / 8880 / 7001 — alternate HTTP admin (Tomcat/JBoss/Node)
	Register(probeHTTP, 80, 81, 3000, 5000, 5800, 5984, 7070, 7001, 8000, 8080, 8081, 8082, 8086, 8123, 8200, 8500, 8880, 8888, 9000, 9090, 9091, 9999, 15672, 16080)
}

// probeHTTP issues a plain HTTP GET against the target.
func probeHTTP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	return s.httpRequest(ctx, target, false)
}

// httpRequest performs an HTTP/HTTPS GET and packages the response into a
// Result. The httpsScheme flag selects the URL scheme; TLS is established
// transparently by the shared http.Transport when needed.
func (s *Stack) httpRequest(ctx context.Context, target Target, httpsScheme bool) (*Result, error) {
	scheme := protocolHTTP
	if httpsScheme {
		scheme = protocolHTTPS
	}

	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("%s://%s/", scheme, addr)

	client := &http.Client{
		Transport: s.httpTransport,
		Timeout:   s.cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, body, redirectChain, err := s.httpRequestFollowRedirects(ctx, client, url, 5)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	headers := make(map[string]string, len(response.Header))
	for k, v := range response.Header {
		headers[k] = strings.Join(v, ", ")
	}

	altSvc := response.Header.Get("Alt-Svc")

	httpResult := &HTTPResult{
		StatusCode:     response.StatusCode,
		Server:         response.Header.Get("Server"),
		Title:          extractTitle(body),
		Headers:        headers,
		Body:           string(body),
		RedirectURL:    response.Header.Get("Location"),
		RedirectChain:  redirectChain,
		Technologies:   detectTechnologies(headers, string(body)),
		AltSvcRaw:      altSvc,
		HTTP3Supported: altSvcAdvertisesHTTP3(altSvc),
		BodySHA256:     sha256Hex(body),
		Security:       extractHTTPSecurity(headers),
	}

	var (
		notFoundHash string
		faviconHash  *int32
		robotsTxt    string
		securityTxt  string
	)

	var auxWg sync.WaitGroup

	auxWg.Add(4)

	go func() {
		defer auxWg.Done()

		if h, ok := s.fetchNotFoundHash(ctx, client, scheme, addr); ok {
			notFoundHash = h
		}
	}()

	go func() {
		defer auxWg.Done()

		if h, ok := s.fetchFaviconHash(ctx, url); ok {
			hash := h
			faviconHash = &hash
		}
	}()

	go func() {
		defer auxWg.Done()

		if r, ok := s.fetchAuxText(ctx, client, scheme, addr, "/robots.txt"); ok {
			robotsTxt = r
		}
	}()

	go func() {
		defer auxWg.Done()

		if sec, ok := s.fetchAuxText(ctx, client, scheme, addr, "/.well-known/security.txt"); ok {
			securityTxt = sec
		}
	}()

	auxWg.Wait()

	httpResult.NotFoundHash = notFoundHash
	httpResult.FaviconHash = faviconHash
	httpResult.RobotsTxt = robotsTxt
	httpResult.SecurityTxt = securityTxt

	result := &Result{
		Target:   target,
		Protocol: scheme,
		HTTP:     httpResult,
	}

	if fp := s.probeONVIF(ctx, client, scheme, addr); fp != nil {
		result.Protocol = fp.Product
		result.Fingerprint = fp
	}

	// Fallback chain: ONVIF (handled above) is the only HTTP probe that
	// runs extra requests before this point. If it didn't produce a
	// fingerprint we try the no-extra-IO derivations from the data we
	// already have — Server header, X-Powered-By / X-Generator headers,
	// <meta generator>, plus a few body/header heuristics in derived.go.
	if result.Fingerprint == nil {
		if fp := fingerprintFromHTTP(httpResult); fp != nil {
			result.Protocol = fp.Product
			result.Fingerprint = fp
		}
	}

	// Port 5000 is shared between Flask debug servers and OpenStack
	// Keystone's public HTTP API. When the generic fingerprint missed,
	// probe `/v3/` once — Keystone always answers with JSON version info.
	if result.Fingerprint == nil && target.Port == 5000 {
		if fp := s.tryOpenStackKeystone(ctx, client, scheme, addr); fp != nil {
			result.Protocol = fp.Product
			result.Fingerprint = fp
		}
	}

	if gq := s.detectGraphQL(ctx, client, scheme, addr); gq != nil {
		result.GraphQL = gq

		if result.Fingerprint == nil {
			result.Protocol = productGraphQL
			result.Fingerprint = &FingerprintResult{Product: productGraphQL}
		}
	}

	result.Components = collectHTTPComponents(httpResult, result.Fingerprint)

	return result, nil
}

// collectHTTPComponents merges the legacy "primary" fingerprint (ONVIF /
// Keystone / Server header) with the full multi-layer stack extracted by
// componentsFromHTTP, so downstream ingest writes every detected layer as
// its own uv_service_fingerprint row.
func collectHTTPComponents(httpResult *HTTPResult, primary *FingerprintResult) []TechComponent {
	var components []TechComponent

	if primary != nil {
		components = append(components, fingerprintToComponent(primary, ComponentSourceProtocolProbe, roleForProduct(primary.Product, ComponentRoleOther)))
	}

	components = append(components, componentsFromHTTP(httpResult)...)

	return dedupComponents(components)
}

// tryOpenStackKeystone performs GET /v3/ and parses the version envelope.
func (s *Stack) tryOpenStackKeystone(ctx context.Context, client *http.Client, scheme, addr string) *FingerprintResult {
	keystoneURL := fmt.Sprintf("%s://%s/v3/", scheme, addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keystoneURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.cfg.UserAgent+"-keystone")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil
	}

	var envelope struct {
		Version struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"version"`
	}

	if jsonErr := json.Unmarshal(body, &envelope); jsonErr != nil {
		return nil
	}

	if envelope.Version.ID == "" || !strings.HasPrefix(strings.ToLower(envelope.Version.ID), "v3") {
		return nil
	}

	return &FingerprintResult{
		Product: "openstack_keystone",
		Version: envelope.Version.ID,
		Edition: envelope.Version.Status,
		RawJSON: mustMarshalJSON(map[string]any{
			"keystone_version": envelope.Version.ID,
			"status":           envelope.Version.Status,
		}),
	}
}

// httpRequestFollowRedirects performs the GET, collecting the redirect chain
// up to maxHops. Returns the final response and consumed body bytes.
func (s *Stack) httpRequestFollowRedirects(ctx context.Context, client *http.Client, startURL string, maxHops int) (*http.Response, []byte, []RedirectStep, error) {
	currentURL, parseStartErr := url.Parse(startURL)
	if parseStartErr != nil {
		return nil, nil, nil, fmt.Errorf("can't parse start URL: %w", parseStartErr)
	}

	var (
		chain    []RedirectStep
		response *http.Response
	)

	for hop := 0; hop <= maxHops; hop++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, currentURL.String(), nil)
		if reqErr != nil {
			return nil, nil, chain, fmt.Errorf("can't build HTTP request: %w", reqErr)
		}

		req.Header.Set("User-Agent", s.cfg.UserAgent)

		resp, doErr := client.Do(req)
		if doErr != nil {
			return nil, nil, chain, fmt.Errorf("can't perform HTTP request: %w", doErr)
		}

		location := resp.Header.Get("Location")

		chain = append(chain, RedirectStep{
			URL:        currentURL.String(),
			StatusCode: resp.StatusCode,
			Location:   location,
		})

		if hop == maxHops || resp.StatusCode < 300 || resp.StatusCode >= 400 || location == "" {
			response = resp

			break
		}

		nextURL, parseErr := url.Parse(location)
		if parseErr != nil {
			response = resp

			break
		}

		resolved := currentURL.ResolveReference(nextURL)

		// Defence-in-depth: refuse to follow a redirect that points at a
		// private/loopback host. The original target is already gated by
		// scanpolicy, but a malicious server could otherwise redirect us
		// to cloud metadata or admin panels on the scanner's own network.
		if isPrivateHost(resolved.Hostname()) {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			response = resp

			break
		}

		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		currentURL = resolved
	}

	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(s.cfg.MaxBody)))
	if readErr != nil {
		return nil, nil, chain, fmt.Errorf("can't read HTTP body: %w", readErr)
	}

	return response, body, chain, nil
}

// fetchAuxText GETs a known small endpoint such as /robots.txt and returns
// its body when status code is 200 and content fits in the body limit.
func (s *Stack) fetchAuxText(ctx context.Context, client *http.Client, scheme, addr, path string) (string, bool) {
	url := fmt.Sprintf("%s://%s%s", scheme, addr, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}

	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	limit := int64(s.cfg.MaxBody)
	if limit > 65536 {
		limit = 65536
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return "", false
	}

	return string(body), len(body) > 0
}

func extractTitle(body []byte) string {
	match := titleRegexp.FindSubmatch(body)
	if len(match) < 2 {
		return ""
	}

	return string(match[1])
}

// sha256Hex returns the hex-encoded SHA-256 of data, or "" for empty input.
func sha256Hex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// fetchNotFoundHash GETs a random path that almost certainly does not
// exist and returns the SHA-256 of the response body. Default error
// pages frequently expose framework or server-version hints (e.g.
// "WordPress" branding on the 404, ASP.NET runtime errors). Returns
// (hash, true) only when the response is a 404 — any other status
// would conflate real content with the error template.
func (s *Stack) fetchNotFoundHash(ctx context.Context, client *http.Client, scheme, addr string) (string, bool) {
	suffix := make([]byte, 16)
	if _, err := rand.Read(suffix); err != nil {
		return "", false
	}

	probeURL := scheme + "://" + addr + "/uv-probe-" + hex.EncodeToString(suffix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", false
	}

	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		return "", false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	if err != nil || len(body) == 0 {
		return "", false
	}

	return sha256Hex(body), true
}

// altSvcAdvertisesHTTP3 reports whether the Alt-Svc header value lists any
// h3 protocol identifier (h3, h3-29, h3-Q050, …). Alt-Svc entries are
// comma-separated `protocol-id=quoted-authority; params`; the id is the
// substring before `=`. Cheap detection without a full parser.
func altSvcAdvertisesHTTP3(value string) bool {
	if value == "" {
		return false
	}

	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)

		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}

		id := strings.ToLower(entry[:eq])
		if id == "h3" || strings.HasPrefix(id, "h3-") {
			return true
		}
	}

	return false
}
