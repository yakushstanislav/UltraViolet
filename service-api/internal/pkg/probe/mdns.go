package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	mdnsBrowseTarget = "_services._dns-sd._udp.local."

	// mdnsCollectWindow caps the time we spend draining responses after the
	// first datagram arrives. Most service announcements show up within
	// ~200ms; 1.5s catches stragglers without stalling the pipeline.
	mdnsCollectWindow = 1500 * time.Millisecond

	// mdnsMaxDatagrams bounds memory if a chatty host floods the socket.
	mdnsMaxDatagrams = 32

	// mdnsReadBuf is large enough for any single mDNS datagram (RFC 6762
	// recommends staying within 1500B, but allow headroom for big TXT RRs).
	mdnsReadBuf = 9000
)

func init() {
	RegisterUDP(probeMDNS, 5353)
}

// probeMDNS sends a unicast PTR browse for "_services._dns-sd._udp.local"
// and aggregates all advertised service types, instance names, SRV targets
// and TXT records that arrive within a short collection window.
func probeMDNS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial mDNS target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	if _, werr := conn.Write(mdnsBuildBrowseQuery()); werr != nil {
		return nil, fmt.Errorf("can't write mDNS query: %w", werr)
	}

	datagrams := mdnsReadDatagrams(conn)
	if len(datagrams) == 0 {
		return nil, errors.New("mdns: no response")
	}

	services, instances, srvByName, txtByName := mdnsAggregate(datagrams)

	if len(services) == 0 && len(instances) == 0 && len(srvByName) == 0 {
		return nil, errors.New("mdns: empty answer set")
	}

	banner := strings.Join(services, "; ")
	if banner == "" {
		banner = "mDNS responder"
	}

	return &Result{
		Target:   target,
		Protocol: "mdns",
		Banner:   banner,
		Fingerprint: &FingerprintResult{
			Product: "mdns",
			Version: banner,
			RawJSON: mustMarshalJSON(map[string]any{
				"services":  services,
				"instances": instances,
				"srv":       srvByName,
				"txt":       txtByName,
			}),
		},
	}, nil
}

// mdnsBuildBrowseQuery returns the wire format of the standard DNS-SD
// service-type enumeration query. ID is 0 per RFC 6762 §18.1, RD bit is
// clear since mDNS responders don't recurse.
func mdnsBuildBrowseQuery() []byte {
	msg := new(dns.Msg)
	msg.Id = 0
	msg.RecursionDesired = false
	msg.Question = []dns.Question{{
		Name:   mdnsBrowseTarget,
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	}}

	wire, err := msg.Pack()
	if err != nil {
		return nil
	}

	return wire
}

// mdnsReadDatagrams drains the socket until the collection window expires
// or mdnsMaxDatagrams is reached. The deadline is reset after every
// successful read so a stream of late responses still get collected.
func mdnsReadDatagrams(conn net.Conn) [][]byte {
	var out [][]byte

	for range mdnsMaxDatagrams {
		_ = conn.SetReadDeadline(time.Now().Add(mdnsCollectWindow))

		buf := make([]byte, mdnsReadBuf)

		n, err := conn.Read(buf)
		if err != nil || n < 12 {
			return out
		}

		out = append(out, buf[:n])
	}

	return out
}

// mdnsAggregate walks every datagram and pulls out service types from PTR
// answers to the browse query, instance names from PTR answers for those
// service types, SRV targets and TXT records keyed by their owner name.
func mdnsAggregate(datagrams [][]byte) ([]string, map[string][]string, map[string]map[string]any, map[string][]string) {
	serviceSet := map[string]struct{}{}
	instances := map[string]map[string]struct{}{}
	srvByName := map[string]map[string]any{}
	txtByName := map[string][]string{}

	for _, raw := range datagrams {
		msg := new(dns.Msg)
		if err := msg.Unpack(raw); err != nil {
			continue
		}

		records := make([]dns.RR, 0, len(msg.Answer)+len(msg.Extra)+len(msg.Ns))
		records = append(records, msg.Answer...)
		records = append(records, msg.Ns...)
		records = append(records, msg.Extra...)

		for _, rr := range records {
			mdnsClassifyRR(rr, serviceSet, instances, srvByName, txtByName)
		}
	}

	services := make([]string, 0, len(serviceSet))
	for s := range serviceSet {
		services = append(services, s)
	}

	sort.Strings(services)

	instancesOut := make(map[string][]string, len(instances))

	for svc, set := range instances {
		list := make([]string, 0, len(set))
		for inst := range set {
			list = append(list, inst)
		}

		sort.Strings(list)

		instancesOut[svc] = list
	}

	return services, instancesOut, srvByName, txtByName
}

// mdnsClassifyRR routes a single RR into one of the per-type aggregators.
// PTR with owner "_services._dns-sd._udp.local" enumerates service types;
// PTR with owner "_x._tcp.local" enumerates instances; SRV/TXT record the
// concrete service endpoint metadata.
func mdnsClassifyRR(rr dns.RR,
	serviceSet map[string]struct{},
	instances map[string]map[string]struct{},
	srvByName map[string]map[string]any,
	txtByName map[string][]string,
) {
	switch v := rr.(type) {
	case *dns.PTR:
		owner := strings.TrimSuffix(strings.ToLower(v.Hdr.Name), ".")
		ptr := strings.TrimSuffix(v.Ptr, ".")

		if owner == strings.TrimSuffix(mdnsBrowseTarget, ".") {
			serviceSet[ptr] = struct{}{}

			return
		}

		if _, ok := instances[owner]; !ok {
			instances[owner] = map[string]struct{}{}
		}

		instances[owner][ptr] = struct{}{}

	case *dns.SRV:
		name := strings.TrimSuffix(v.Hdr.Name, ".")
		srvByName[name] = map[string]any{
			"target":   strings.TrimSuffix(v.Target, "."),
			"port":     v.Port,
			"priority": v.Priority,
			"weight":   v.Weight,
		}

	case *dns.TXT:
		name := strings.TrimSuffix(v.Hdr.Name, ".")
		txtByName[name] = append(txtByName[name], v.Txt...)
	}
}
