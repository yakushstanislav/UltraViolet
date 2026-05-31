package screenshot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CaptureResult holds the rendered thumbnail plus the encoded dimensions.
type CaptureResult struct {
	JPEG     []byte
	Width    int
	Height   int
	Duration time.Duration
}

// Service captures HTTP screenshots through a headless-Chromium instance.
type Service struct {
	Config Config
	Gate   *Gate
}

// New builds a Service from configuration. Returns a nil Gate when disabled,
// which the worker uses as the "feature off" signal.
func New(cfg Config) *Service {
	if cfg.Enabled {
		if cfg.Timeout <= 0 {
			cfg.Timeout = 15 * time.Second
		}

		if cfg.NavigateTimeout <= 0 {
			cfg.NavigateTimeout = cfg.Timeout
		}

		if cfg.ViewportWidth <= 0 {
			cfg.ViewportWidth = 1280
		}

		if cfg.ViewportHeight <= 0 {
			cfg.ViewportHeight = 800
		}

		if cfg.ThumbnailWidth <= 0 {
			cfg.ThumbnailWidth = cfg.ViewportWidth
		}

		if cfg.JPEGQuality <= 0 || cfg.JPEGQuality > 100 {
			cfg.JPEGQuality = 80
		}
	}

	return &Service{
		Config: cfg,
		Gate:   NewGate(cfg),
	}
}

// ErrDisabled is returned by Capture when the feature is turned off.
var ErrDisabled = errors.New("screenshot feature disabled")

// Capture navigates a fresh Chromium target to url and returns a JPEG
// thumbnail. The render finishes when Page.loadEventFired arrives or the
// per-call timeout expires; on timeout the partially-rendered page is still
// captured so transient slow loaders don't waste the slot completely.
func (s *Service) Capture(ctx context.Context, targetURL string) (*CaptureResult, error) {
	if s == nil || !s.Config.Enabled {
		return nil, ErrDisabled
	}

	if targetURL == "" {
		return nil, errors.New("target URL is empty")
	}

	wsURL, err := discoverBrowserWS(ctx, s.Config.ChromiumURL)
	if err != nil {
		return nil, err
	}

	sessionCtx, cancel := context.WithTimeout(ctx, s.Config.Timeout)
	defer cancel()

	session, err := dialCDP(sessionCtx, wsURL)
	if err != nil {
		return nil, err
	}

	defer session.close()

	targetID, sessionID, err := openTarget(sessionCtx, session)
	if err != nil {
		return nil, err
	}

	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer closeCancel()

		_, _ = session.call(closeCtx, "Target.closeTarget", map[string]any{"targetId": targetID}, "")
	}()

	scaleFactor := 1.0
	if s.Config.ThumbnailWidth > 0 && s.Config.ThumbnailWidth < s.Config.ViewportWidth {
		scaleFactor = float64(s.Config.ThumbnailWidth) / float64(s.Config.ViewportWidth)
	}

	if _, viewportErr := session.call(sessionCtx, "Emulation.setDeviceMetricsOverride", map[string]any{
		"width":             s.Config.ViewportWidth,
		"height":            s.Config.ViewportHeight,
		"deviceScaleFactor": scaleFactor,
		"mobile":            false,
	}, sessionID); viewportErr != nil {
		return nil, fmt.Errorf("can't set viewport: %w", viewportErr)
	}

	if s.Config.UserAgent != "" {
		if _, uaErr := session.call(sessionCtx, "Network.setUserAgentOverride", map[string]any{
			"userAgent": s.Config.UserAgent,
		}, sessionID); uaErr != nil {
			return nil, fmt.Errorf("can't override user agent: %w", uaErr)
		}
	}

	if _, enableErr := session.call(sessionCtx, "Page.enable", struct{}{}, sessionID); enableErr != nil {
		return nil, fmt.Errorf("can't enable Page domain: %w", enableErr)
	}

	start := time.Now()

	navCtx, navCancel := context.WithTimeout(sessionCtx, s.Config.NavigateTimeout)

	navErr := session.callAndWaitEvent(navCtx, "Page.navigate", map[string]any{"url": targetURL}, sessionID, "Page.loadEventFired")

	navCancel()

	// Even when load times out we still capture what's painted — many slow
	// HTTP endpoints (ICS panels, login forms behind XHR) never fire load but
	// have meaningful screenshot content.
	if navErr != nil && !errors.Is(navErr, context.DeadlineExceeded) && !errors.Is(navErr, context.Canceled) {
		return nil, fmt.Errorf("can't navigate to target: %w", navErr)
	}

	jpeg, w, h, err := captureScreenshot(sessionCtx, session, sessionID, s.Config.JPEGQuality)
	if err != nil {
		return nil, err
	}

	return &CaptureResult{
		JPEG:     jpeg,
		Width:    w,
		Height:   h,
		Duration: time.Since(start),
	}, nil
}

func openTarget(ctx context.Context, session *cdpSession) (string, string, error) {
	raw, err := session.call(ctx, "Target.createTarget", map[string]any{
		"url": "about:blank",
	}, "")
	if err != nil {
		return "", "", fmt.Errorf("can't create target: %w", err)
	}

	var created struct {
		TargetID string `json:"targetId"`
	}

	if decodeErr := json.Unmarshal(raw, &created); decodeErr != nil {
		return "", "", fmt.Errorf("can't decode createTarget result: %w", decodeErr)
	}

	if created.TargetID == "" {
		return "", "", errors.New("createTarget returned empty target id")
	}

	raw, err = session.call(ctx, "Target.attachToTarget", map[string]any{
		"targetId": created.TargetID,
		"flatten":  true,
	}, "")
	if err != nil {
		return "", "", fmt.Errorf("can't attach to target: %w", err)
	}

	var attached struct {
		SessionID string `json:"sessionId"`
	}

	if decodeErr := json.Unmarshal(raw, &attached); decodeErr != nil {
		return "", "", fmt.Errorf("can't decode attachToTarget result: %w", decodeErr)
	}

	if attached.SessionID == "" {
		return "", "", errors.New("attachToTarget returned empty session id")
	}

	return created.TargetID, attached.SessionID, nil
}

func captureScreenshot(ctx context.Context, session *cdpSession, sessionID string, quality int) ([]byte, int, int, error) {
	raw, err := session.call(ctx, "Page.captureScreenshot", map[string]any{
		"format":      "jpeg",
		"quality":     quality,
		"fromSurface": true,
	}, sessionID)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("can't capture screenshot: %w", err)
	}

	var shot struct {
		Data string `json:"data"`
	}

	if decodeErr := json.Unmarshal(raw, &shot); decodeErr != nil {
		return nil, 0, 0, fmt.Errorf("can't decode screenshot result: %w", decodeErr)
	}

	jpeg, err := base64.StdEncoding.DecodeString(shot.Data)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("can't decode screenshot bytes: %w", err)
	}

	w, h, err := decodeJPEGDimensions(jpeg)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("can't parse JPEG dimensions: %w", err)
	}

	return jpeg, w, h, nil
}
