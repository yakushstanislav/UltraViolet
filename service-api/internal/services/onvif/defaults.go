package onvif

import "time"

const (
	defaultRequestTimeout       = 15 * time.Second
	defaultLabPerAttemptTimeout = 6 * time.Second
	defaultLabInterAttemptDelay = 100 * time.Millisecond
)
