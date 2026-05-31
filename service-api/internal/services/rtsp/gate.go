package rtsp

// SnapshotGate limits concurrent FFmpeg RTSP snapshot captures.
type SnapshotGate struct {
	sem chan struct{}
}

// NewSnapshotGate builds a gate when enabled; returns nil when disabled.
func NewSnapshotGate(cfg Config) *SnapshotGate {
	if !cfg.Enabled {
		return nil
	}

	n := cfg.MaxConcurrent
	if n < 1 {
		n = 1
	}

	return &SnapshotGate{sem: make(chan struct{}, n)}
}

// TryAcquire grabs one slot. On success release must be called exactly once.
func (g *SnapshotGate) TryAcquire() (release func(), busy bool) {
	if g == nil {
		return func() {}, false
	}

	select {
	case g.sem <- struct{}{}:
		return func() { <-g.sem }, false
	default:
		return nil, true
	}
}
