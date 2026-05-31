package forwarddns

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/dnsclient"
)

// Record is a single resolved DNS entry for a hostname.
type Record struct {
	Type  string // "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"
	Name  string // queried hostname (apex for NS/SOA)
	Value string // resolved answer
}

// perNameTypes are queried against the hostname itself.
var perNameTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypeMX,
	dns.TypeTXT,
	dns.TypeCAA,
}

// perApexTypes describe the zone, not the leaf name, so they are queried once
// per apex domain and reused across every subdomain in the batch via the
// shared dnsclient cache.
var perApexTypes = []uint16{
	dns.TypeNS,
	dns.TypeSOA,
}

// LookupAll queries the configured record set for each hostname in parallel and
// returns map[hostname][]Record. The observer, if non-nil, receives one
// callback per query for metrics. Per-query errors are best-effort: a hostname
// with no resolvable records maps to an empty slice.
func LookupAll(
	ctx context.Context,
	cfg Config,
	hostnames []string,
	observer dnsclient.Observer,
) (map[string][]Record, error) {
	if len(hostnames) == 0 {
		return map[string][]Record{}, nil
	}

	client, err := dnsclient.New(dnsclient.Config{
		Resolvers:       cfg.Resolvers,
		PerQueryTimeout: cfg.PerQueryTimeout,
		Retries:         cfg.Retries,
		CacheTTL:        cfg.CacheTTL,
		Observer:        observer,
	})
	if err != nil {
		return nil, err
	}

	batchTimeout := cfg.Timeout
	if batchTimeout <= 0 {
		batchTimeout = 2 * time.Minute
	}

	subCtx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()

	nWorkers := cfg.Threads
	if nWorkers < 1 {
		nWorkers = 8
	}

	if nWorkers > len(hostnames) {
		nWorkers = len(hostnames)
	}

	out := make(map[string][]Record, len(hostnames))

	var mu sync.Mutex

	g, gctx := errgroup.WithContext(subCtx)

	for wid := range nWorkers {
		g.Go(func() error {
			for i := wid; i < len(hostnames); i += nWorkers {
				name := hostnames[i]
				records := lookupOne(gctx, client, name)

				mu.Lock()
				out[name] = records
				mu.Unlock()
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return out, err
	}

	return out, nil
}

// lookupOne resolves the per-name record set against name, the zone-level
// NS/SOA against its apex, plus SRV if the name is a DNS-SD label.
func lookupOne(ctx context.Context, client *dnsclient.Client, name string) []Record {
	fqdn := dns.Fqdn(name)
	records := make([]Record, 0, 8)

	for _, qtype := range perNameTypes {
		resp, err := client.Query(ctx, fqdn, qtype)
		if err != nil || resp == nil {
			continue
		}

		records = append(records, extractRecords(name, qtype, resp.Answer)...)
	}

	apex := apexOf(name)
	apexFqdn := dns.Fqdn(apex)

	for _, qtype := range perApexTypes {
		resp, err := client.Query(ctx, apexFqdn, qtype)
		if err != nil || resp == nil {
			continue
		}

		records = append(records, extractRecords(apex, qtype, resp.Answer)...)
	}

	if isDNSSDName(name) {
		resp, err := client.Query(ctx, fqdn, dns.TypeSRV)
		if err == nil && resp != nil {
			records = append(records, extractRecords(name, dns.TypeSRV, resp.Answer)...)
		}
	}

	return records
}

// apexOf returns the rightmost label.tld pair of name. It mirrors the eTLD
// heuristic used by the scanner's CT-log seeding — pulling the full public
// suffix list is overkill for zone-level NS/SOA dedup.
func apexOf(name string) string {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return name
	}

	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

// extractRecords flattens RRs of the requested type into Record entries.
// CNAME/MX/NS/SRV/SOA targets have their trailing dots stripped to match the
// shape used by net.LookupMX/LookupNS callers historically saw.
func extractRecords(name string, qtype uint16, rrs []dns.RR) []Record {
	var out []Record

	for _, rr := range rrs {
		rec, ok := rrToRecord(name, qtype, rr)
		if !ok {
			continue
		}

		out = append(out, rec)
	}

	return out
}

// rrToRecord converts a single RR into a Record entry, returning false when
// the RR type doesn't match the query (resolver may include glue records).
func rrToRecord(name string, qtype uint16, rr dns.RR) (Record, bool) {
	switch v := rr.(type) {
	case *dns.A:
		if qtype != dns.TypeA {
			return Record{}, false
		}

		return Record{Type: "A", Name: name, Value: v.A.String()}, true

	case *dns.AAAA:
		if qtype != dns.TypeAAAA {
			return Record{}, false
		}

		return Record{Type: "AAAA", Name: name, Value: v.AAAA.String()}, true

	case *dns.CNAME:
		if qtype != dns.TypeCNAME {
			return Record{}, false
		}

		return Record{Type: "CNAME", Name: name, Value: strings.TrimSuffix(v.Target, ".")}, true

	case *dns.MX:
		if qtype != dns.TypeMX {
			return Record{}, false
		}

		return Record{
			Type:  "MX",
			Name:  name,
			Value: fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, ".")),
		}, true

	case *dns.NS:
		if qtype != dns.TypeNS {
			return Record{}, false
		}

		return Record{Type: "NS", Name: name, Value: strings.TrimSuffix(v.Ns, ".")}, true

	case *dns.TXT:
		if qtype != dns.TypeTXT {
			return Record{}, false
		}

		return Record{Type: "TXT", Name: name, Value: strings.Join(v.Txt, "")}, true

	case *dns.SOA:
		if qtype != dns.TypeSOA {
			return Record{}, false
		}

		return Record{
			Type: "SOA",
			Name: name,
			Value: fmt.Sprintf("%s %s %d",
				strings.TrimSuffix(v.Ns, "."),
				strings.TrimSuffix(v.Mbox, "."),
				v.Serial,
			),
		}, true

	case *dns.CAA:
		if qtype != dns.TypeCAA {
			return Record{}, false
		}

		return Record{
			Type:  "CAA",
			Name:  name,
			Value: fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value),
		}, true

	case *dns.SRV:
		if qtype != dns.TypeSRV {
			return Record{}, false
		}

		return Record{
			Type: "SRV",
			Name: name,
			Value: fmt.Sprintf("%d %d %d %s",
				v.Priority, v.Weight, v.Port,
				strings.TrimSuffix(v.Target, "."),
			),
		}, true
	}

	return Record{}, false
}

// isDNSSDName reports whether name looks like a DNS-SD service label,
// e.g. "_ldap._tcp.example.com" — these are the only names where an SRV
// query is meaningful, and skipping it on regular hostnames cuts the query
// count.
func isDNSSDName(name string) bool {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}

	return strings.HasPrefix(labels[0], "_") && (labels[1] == "_tcp" || labels[1] == "_udp")
}
