package rtsp

import "time"

// Config controls RTSP snapshot capture endpoints.
type Config struct {
	Enabled       bool          `env:"RTSP_SNAPSHOT_ENABLED" env-default:"true"`
	FFmpegPath    string        `env:"RTSP_SNAPSHOT_FFMPEG" env-default:"ffmpeg"`
	ExecTimeout   time.Duration `env:"RTSP_SNAPSHOT_TIMEOUT" env-default:"12s"`
	MaxConcurrent int           `env:"RTSP_SNAPSHOT_MAX_CONCURRENT" env-default:"4"`
}
