package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const onvifMetricUnknown = "unknown"

var (
	onvifCommandTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "uv_onvif_command_total",
		Help: "ONVIF SOAP command outcomes (low-cardinality labels).",
	}, []string{"command", "outcome"})

	onvifRTSPSnapshotTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "uv_onvif_rtsp_snapshot_total",
		Help: "ONVIF-assisted RTSP JPEG snapshot outcomes.",
	}, []string{"outcome"})
)

// RecordONVIFCommand increments uv_onvif_command_total.
func RecordONVIFCommand(command, outcome string) {
	if command == "" {
		command = onvifMetricUnknown
	}

	if outcome == "" {
		outcome = onvifMetricUnknown
	}

	onvifCommandTotal.WithLabelValues(command, outcome).Inc()
}

// RecordONVIFRTSPSnapshot increments uv_onvif_rtsp_snapshot_total.
func RecordONVIFRTSPSnapshot(outcome string) {
	if outcome == "" {
		outcome = onvifMetricUnknown
	}

	onvifRTSPSnapshotTotal.WithLabelValues(outcome).Inc()
}
