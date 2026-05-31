// Package worker hosts the long-running scanner background loop and the Job
// abstraction used to plug new periodic tasks into it.
package worker

import "context"

// Job is one periodic task driven by the worker loop. Tick returns didWork=true
// if the call performed useful work (e.g. claimed a scan from the queue); the
// loop uses this to decide whether to spin again immediately or sleep until
// the next tick.
type Job interface {
	Name() string
	Tick(ctx context.Context) (didWork bool, err error)
}
