package onvif

// CommandGate limits concurrent ONVIF SOAP calls.
type CommandGate struct {
	sem chan struct{}
}

// NewCommandGate builds a gate when enabled; returns nil when disabled.
func NewCommandGate(cfg Config) *CommandGate {
	if !cfg.Enabled {
		return nil
	}

	n := cfg.MaxConcurrent
	if n < 1 {
		n = 1
	}

	return &CommandGate{sem: make(chan struct{}, n)}
}

// TryAcquire grabs one slot. On success release must be called exactly once.
func (g *CommandGate) TryAcquire() (release func(), busy bool) {
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
