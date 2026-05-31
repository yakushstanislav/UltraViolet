package probe

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const productDNS = "dns"

// chaosFingerprintQueries is the ordered list of CHAOS-class TXT queries
// issued against every candidate DNS server. Each label targets a different
// resolver family (BIND, Unbound, Knot/PowerDNS, BIND9 again with authors).
// Order is preserved so banner strings stay reproducible.
var chaosFingerprintQueries = []string{
	"version.bind.",
	"hostname.bind.",
	"id.server.",
	"authors.bind.",
}

// dnsQueryReadTimeout caps the per-query wait so one unresponsive
// fingerprint query can't burn the whole probe budget.
const dnsQueryReadTimeout = 2 * time.Second

// errDNSTruncated signals that the only valid response carried TC=1.
// UDP callers can use this hint to retry the probe over TCP.
var errDNSTruncated = errors.New("dns: response truncated")

func init() {
	Register(probeDNSTCP, 53)
}

// probeDNSTCP fingerprints a TCP/53 DNS server by issuing the standard CHAOS
// TXT fingerprint queries on a single multiplexed TCP connection and
// aggregating responses. Falls through to error when nothing valid comes back
// — sockets that merely accept connect but ignore DNS framing are rejected
// rather than reported as "DNS detected".
func probeDNSTCP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial DNS target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	answers, rcode, ra, err := dnsRunFingerprint(&dns.Conn{Conn: conn})
	if err != nil {
		return nil, err
	}

	return dnsBuildResult(target, productDNS, answers, rcode, ra), nil
}

// dnsBuildCHAOSQuery builds a CHAOS-class TXT query for the supplied name,
// with a random transaction ID, RD bit set, and EDNS0 (4096-byte UDP buffer).
func dnsBuildCHAOSQuery(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   name,
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassCHAOS,
	}}

	msg.SetEdns0(4096, false)

	return msg
}

// dnsRunFingerprint issues every CHAOS TXT fingerprint query over co and
// returns the collected non-empty TXT strings keyed by query label, the last
// observed RCODE and the RA flag.
//
// Queries are pipelined: all messages are written first, then responses are
// read and matched by transaction ID. This collapses N×RTT to 1×RTT for the
// common case where the server responds quickly to all queries.
//
// A target is treated as a real DNS server only when at least one query
// returns NOERROR or NXDOMAIN with a matching transaction ID. SERVFAIL /
// REFUSED / timeout responses are rejected. If every response we got was
// truncated, the function returns errDNSTruncated so UDP callers can retry
// over TCP.
func dnsRunFingerprint(co *dns.Conn) (map[string][]string, int, bool, error) {
	type pendingEntry struct {
		name string
	}

	pending := make(map[uint16]pendingEntry, len(chaosFingerprintQueries))

	for _, name := range chaosFingerprintQueries {
		req := dnsBuildCHAOSQuery(name)

		_ = co.SetWriteDeadline(time.Now().Add(dnsQueryReadTimeout))

		if werr := co.WriteMsg(req); werr != nil {
			continue
		}

		pending[req.Id] = pendingEntry{name: name}
	}

	answers := make(map[string][]string, len(chaosFingerprintQueries))
	rcode := dns.RcodeSuccess
	ra := false
	anyValid := false
	sawTruncated := false

	for len(pending) > 0 {
		_ = co.SetReadDeadline(time.Now().Add(dnsQueryReadTimeout))

		resp, rerr := co.ReadMsg()
		if rerr != nil || resp == nil {
			break
		}

		entry, ok := pending[resp.Id]
		if !ok {
			continue
		}

		delete(pending, resp.Id)

		if resp.Truncated {
			sawTruncated = true

			continue
		}

		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			continue
		}

		anyValid = true
		rcode = resp.Rcode
		ra = resp.RecursionAvailable

		values := dnsExtractTXT(resp.Answer)
		if len(values) > 0 {
			answers[strings.TrimSuffix(entry.name, ".")] = values
		}
	}

	if !anyValid {
		if sawTruncated {
			return nil, 0, false, errDNSTruncated
		}

		return nil, 0, false, errors.New("dns: no valid responses")
	}

	return answers, rcode, ra, nil
}

// dnsExtractTXT flattens TXT RRs from a DNS answer slice. Non-TXT records
// are ignored.
func dnsExtractTXT(rrs []dns.RR) []string {
	var out []string

	for _, rr := range rrs {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		out = append(out, txt.Txt...)
	}

	return out
}

// dnsBuildResult assembles a Result from the fingerprint pass. The Banner
// favours the version.bind answer; if absent, a generic "DNS server" label
// keeps the row searchable while RawJSON preserves all observed labels.
func dnsBuildResult(target Target, product string, answers map[string][]string, rcode int, ra bool) *Result {
	versions := answers["version.bind"]

	banner := strings.Join(versions, "; ")
	if banner == "" {
		banner = "DNS server"
	}

	labels := make([]string, 0, len(answers))
	for k := range answers {
		labels = append(labels, k)
	}

	sort.Strings(labels)

	return &Result{
		Target:   target,
		Protocol: productDNS,
		Banner:   banner,
		Fingerprint: &FingerprintResult{
			Product: product,
			Version: strings.Join(versions, "; "),
			RawJSON: mustMarshalJSON(map[string]any{
				"answers":             answers,
				"answers_labels":      labels,
				"rcode":               rcode,
				"rcode_text":          dns.RcodeToString[rcode],
				"recursion_available": ra,
			}),
		},
	}
}
