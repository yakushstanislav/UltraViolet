// Package rtsp owns RTSP snapshot concurrency limits and capture settings.
package rtsp

import "time"

// Service holds RTSP snapshot infrastructure shared by host media handlers.
type Service struct {
	Config       Config
	SnapshotGate *SnapshotGate
}

// New builds a Service from configuration.
func New(cfg Config) *Service {
	if cfg.Enabled {
		if cfg.ExecTimeout <= 0 {
			cfg.ExecTimeout = 12 * time.Second
		}

		if cfg.FFmpegPath == "" {
			cfg.FFmpegPath = "ffmpeg"
		}
	}

	return &Service{
		Config:       cfg,
		SnapshotGate: NewSnapshotGate(cfg),
	}
}
