// Package pivot builds force-graph payloads from shared artifact matches.
package pivot

import (
	"context"
	"fmt"
	"net/netip"

	pivotdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/pivot"
	pivotrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/pivot"
)

const (
	nodeKindHost     = "host"
	nodeKindService  = "service"
	nodeKindArtifact = "artifact"
)

// Service answers pivot graph queries.
type Service struct {
	pivotRepository pivotrepository.Repository
}

// New builds a Service.
func New(pivotRepository pivotrepository.Repository) *Service {
	return &Service{pivotRepository: pivotRepository}
}

// Find returns a graph centered on the requested artifact.
func (s *Service) Find(ctx context.Context, kind, value string, limit uint64) (pivotdto.Response, error) {
	result, err := s.pivotRepository.FindByArtifact(ctx, kind, value, limit)
	if err != nil {
		return pivotdto.Response{}, fmt.Errorf("can't find pivot hits: %w", err)
	}

	resp := pivotdto.Response{
		Kind:      kind,
		Value:     value,
		Total:     result.Total,
		Truncated: result.Total > uint64(len(result.Hits)),
		Nodes:     make([]pivotdto.Node, 0, len(result.Hits)*2+1),
		Edges:     make([]pivotdto.Edge, 0, len(result.Hits)*2),
	}

	artifactID := artifactNodeID(kind, value)
	resp.Nodes = append(resp.Nodes, pivotdto.Node{
		ID:    artifactID,
		Kind:  nodeKindArtifact,
		Label: truncateLabel(value, kind),
	})

	hostSeen := make(map[uint64]string, len(result.Hits))
	serviceSeen := make(map[uint64]struct{}, len(result.Hits))

	for _, hit := range result.Hits {
		hostIP := hostIPLiteral(hit.IP)

		hostNodeID, ok := hostSeen[hit.HostID]
		if !ok {
			hostNodeID = fmt.Sprintf("host:%d", hit.HostID)

			node := pivotdto.Node{
				ID:     hostNodeID,
				Kind:   nodeKindHost,
				Label:  hostIP,
				IP:     hostIP,
				HostID: hit.HostID,
			}

			if hit.CountryCode.Valid {
				node.CountryCode = hit.CountryCode.String
			}

			resp.Nodes = append(resp.Nodes, node)
			hostSeen[hit.HostID] = hostNodeID
		}

		if _, seen := serviceSeen[hit.ServiceID]; seen {
			continue
		}

		serviceSeen[hit.ServiceID] = struct{}{}

		serviceNodeID := fmt.Sprintf("service:%d", hit.ServiceID)

		svcNode := pivotdto.Node{
			ID:        serviceNodeID,
			Kind:      nodeKindService,
			Label:     fmt.Sprintf("%s:%d", hostIP, hit.Port),
			IP:        hostIP,
			HostID:    hit.HostID,
			ServiceID: hit.ServiceID,
			Port:      hit.Port,
			Transport: hit.Transport,
			RiskScore: hit.RiskScore,
		}

		if hit.Protocol.Valid {
			svcNode.Protocol = hit.Protocol.String
		}

		if hit.Title.Valid {
			svcNode.Title = hit.Title.String
		}

		resp.Nodes = append(resp.Nodes, svcNode)

		resp.Edges = append(resp.Edges,
			pivotdto.Edge{Source: artifactID, Target: serviceNodeID, Kind: kind},
			pivotdto.Edge{Source: hostNodeID, Target: serviceNodeID, Kind: "hosts_service"},
		)
	}

	return resp, nil
}

func artifactNodeID(kind, value string) string {
	return fmt.Sprintf("artifact:%s:%s", kind, value)
}

func truncateLabel(value, kind string) string {
	switch kind {
	case pivotdto.KindTLSFingerprint, pivotdto.KindBodySHA256:
		if len(value) > 12 {
			return value[:12]
		}
	case pivotdto.KindJARM:
		if len(value) > 10 {
			return value[:10]
		}
	case pivotdto.KindJA3S, pivotdto.KindJA4S:
		if len(value) > 8 {
			return value[:8]
		}
	}

	return value
}

func hostIPLiteral(ip string) string {
	if prefix, err := netip.ParsePrefix(ip); err == nil {
		return prefix.Addr().String()
	}

	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.String()
	}

	return ip
}
