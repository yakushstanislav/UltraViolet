package onvif

import (
	"fmt"
	"sync"
	"time"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"
)

const cacheMaxEntries = 512

// CachedEnvelope is a cached ONVIF HTTP response body.
type CachedEnvelope struct {
	StatusCode  int
	ContentType string
	Body        string
	Truncated   bool
}

type cachedEnvelope struct {
	statusCode  int
	contentType string
	body        string
	truncated   bool
	expires     time.Time
}

// ResponseCache stores idempotent ONVIF command responses.
type ResponseCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*cachedEnvelope
}

// NewResponseCache builds a cache when ttl > 0.
func NewResponseCache(ttl time.Duration) *ResponseCache {
	if ttl <= 0 {
		return nil
	}

	return &ResponseCache{
		ttl: ttl,
		m:   make(map[string]*cachedEnvelope),
	}
}

// CommandCacheable reports whether a command response may be cached.
func CommandCacheable(req hostdto.ONVIFCommandRequest) bool {
	if req.Password != "" {
		return false
	}

	switch req.Command {
	case "get_system_date_and_time", "get_device_information", "get_hostname":
		return true
	default:
		return false
	}
}

// CacheKey builds a stable cache key for one host and request shape.
func CacheKey(hostID uint64, req hostdto.ONVIFCommandRequest) string {
	return fmt.Sprintf("%d|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		hostID,
		req.Port,
		req.Scheme,
		req.Command,
		req.DevicePath,
		req.MediaServicePath,
		req.ImagingServicePath,
		req.PTZServicePath,
		req.User,
		req.AuthMode,
		req.Transport,
	)
}

// Get returns a cached envelope when present and not expired.
func (c *ResponseCache) Get(key string) (CachedEnvelope, bool) {
	if c == nil {
		return CachedEnvelope{}, false
	}

	c.mu.Lock()

	defer c.mu.Unlock()

	e, ok := c.m[key]
	if !ok {
		return CachedEnvelope{}, false
	}

	if time.Now().After(e.expires) {
		delete(c.m, key)

		return CachedEnvelope{}, false
	}

	return CachedEnvelope{
		StatusCode:  e.statusCode,
		ContentType: e.contentType,
		Body:        e.body,
		Truncated:   e.truncated,
	}, true
}

// Set stores one envelope until ttl elapses.
func (c *ResponseCache) Set(key string, v CachedEnvelope) {
	if c == nil {
		return
	}

	c.mu.Lock()

	defer c.mu.Unlock()

	c.m[key] = &cachedEnvelope{
		statusCode:  v.StatusCode,
		contentType: v.ContentType,
		body:        v.Body,
		truncated:   v.Truncated,
		expires:     time.Now().Add(c.ttl),
	}

	if len(c.m) <= cacheMaxEntries {
		return
	}

	now := time.Now()

	for k, ent := range c.m {
		if now.After(ent.expires) {
			delete(c.m, k)
		}

		if len(c.m) <= cacheMaxEntries*3/4 {
			return
		}
	}

	for k := range c.m {
		delete(c.m, k)

		if len(c.m) <= cacheMaxEntries*3/4 {
			return
		}
	}
}
