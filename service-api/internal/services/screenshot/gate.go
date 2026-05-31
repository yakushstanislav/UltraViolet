package screenshot

import "context"

// Gate limits the number of concurrent CDP render sessions so a flood of
// pending jobs can't overwhelm the shared headless-Chromium container.
type Gate struct {
	sem chan struct{}
}

// NewGate builds a gate when enabled; returns nil when disabled.
func NewGate(cfg Config) *Gate {
	if !cfg.Enabled {
		return nil
	}

	n := cfg.MaxConcurrent
	if n < 1 {
		n = 1
	}

	return &Gate{sem: make(chan struct{}, n)}
}

// Acquire blocks until a slot is available or ctx is canceled. The returned
// release must be called exactly once.
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	if g == nil {
		return func() {}, nil
	}

	select {
	case g.sem <- struct{}{}:
		return func() { <-g.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
