package host

import (
	"context"
	"net/netip"

	hostrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
)

// HostByIP returns the host row for an IP without loading services.
func (s *Service) HostByIP(ctx context.Context, ip netip.Addr) (*hostrepository.Host, error) {
	return s.hostRepository.GetByIP(ctx, ip)
}

// HasONVIFEligiblePort reports whether the host exposes ONVIF on the given port.
func (s *Service) HasONVIFEligiblePort(ctx context.Context, hostID uint64, port uint16) (bool, error) {
	return s.serviceRepository.HostHasONVIFEligiblePort(ctx, hostID, port)
}

// HasRTSPOnPort reports whether the host exposes RTSP on the given port and transport.
func (s *Service) HasRTSPOnPort(
	ctx context.Context,
	hostID uint64,
	port uint16,
	transport servicerepository.Transport,
) (bool, error) {
	return s.serviceRepository.HostHasRTSPOnPort(ctx, hostID, port, transport)
}
