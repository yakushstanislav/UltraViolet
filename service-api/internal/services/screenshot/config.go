// Package screenshot owns headless-Chromium screenshot capture for HTTP
// services. It speaks Chrome DevTools Protocol over WebSocket directly so the
// service binary stays free of heavyweight browser-automation dependencies.
package screenshot

import "time"

// Config controls thumbnail rendering.
type Config struct {
	Enabled         bool          `env:"HTTP_SCREENSHOT_ENABLED"          env-default:"true"`
	ChromiumURL     string        `env:"HTTP_SCREENSHOT_CHROMIUM_URL"     env-default:"http://chromium:9222"`
	Timeout         time.Duration `env:"HTTP_SCREENSHOT_TIMEOUT"          env-default:"15s"`
	NavigateTimeout time.Duration `env:"HTTP_SCREENSHOT_NAVIGATE_TIMEOUT" env-default:"10s"`
	MaxConcurrent   int           `env:"HTTP_SCREENSHOT_MAX_CONCURRENT"   env-default:"4"`
	ViewportWidth   int           `env:"HTTP_SCREENSHOT_VIEWPORT_WIDTH"   env-default:"1280"`
	ViewportHeight  int           `env:"HTTP_SCREENSHOT_VIEWPORT_HEIGHT"  env-default:"800"`
	ThumbnailWidth  int           `env:"HTTP_SCREENSHOT_THUMBNAIL_WIDTH"  env-default:"640"`
	JPEGQuality     int           `env:"HTTP_SCREENSHOT_JPEG_QUALITY"     env-default:"80"`
	UserAgent       string        `env:"HTTP_SCREENSHOT_USER_AGENT"       env-default:"UltraViolet/1.0 (+screenshot)"`
}
