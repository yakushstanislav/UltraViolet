package events

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var eventsDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "uv_events_dropped_total",
	Help: "Realtime events dropped because a subscriber buffer was full",
}, []string{"conn_id"})
