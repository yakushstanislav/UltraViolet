package portscan

import "context"

// Stream is what a Discoverer hands back: a channel of open ports plus a
// Wait function the caller invokes once the channel is drained.
//
// Wait blocks until any background goroutine or subprocess settles and
// returns the first fatal error encountered, or nil on a clean finish.
type Stream struct {
	Ports <-chan OpenPort
	Wait  func() error
}

// Discoverer is the common contract for any port-discovery backend
// (slow TCP-connect, masscan, zmap, …).
//
// Implementations may launch goroutines or external processes; callers
// must consume Stream.Ports until close and then invoke Stream.Wait.
type Discoverer interface {
	Discover(ctx context.Context, cidr string, ports []uint16) (*Stream, error)
}

// noopWait is a convenience for backends with no background work to settle.
func noopWait() error { return nil }
