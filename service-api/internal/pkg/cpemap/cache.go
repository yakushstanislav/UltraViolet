package cpemap

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Loader reloads the product map from persistent storage.
type Loader interface {
	LoadAll(ctx context.Context) (map[string][]Coord, error)
}

const defaultRefreshInterval = 60 * time.Second

var (
	cacheMu        sync.RWMutex
	cachedMap      map[string][]Coord
	useBuiltinOnly bool
	loader         Loader
	refreshOnce    sync.Once
)

// Init configures product-map lookup. When builtinOnly is true, Lookup reads
// only from the compiled-in map (bootstrap / tests without DB seed).
func Init(productMapLoader Loader, builtinOnly bool) {
	loader = productMapLoader
	useBuiltinOnly = builtinOnly
	cachedMap = BuiltinMap()
}

// Reload replaces the in-memory map from the loader. No-op when builtinOnly.
func Reload(ctx context.Context) error {
	if useBuiltinOnly || loader == nil {
		return nil
	}

	return refresh(ctx)
}

// StartRefresh launches a background reload loop. No-op when builtinOnly was
// set in Init or loader is nil.
func StartRefresh(ctx context.Context, logger *zap.SugaredLogger, interval time.Duration) {
	if useBuiltinOnly || loader == nil {
		return
	}

	if interval <= 0 {
		interval = defaultRefreshInterval
	}

	refreshOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := refresh(ctx); err != nil && logger != nil {
						logger.Warnw("cpemap refresh failed", zap.Error(err))
					}
				}
			}
		}()
	})
}

func refresh(ctx context.Context) error {
	loaded, err := loader.LoadAll(ctx)
	if err != nil {
		return err
	}

	if len(loaded) == 0 {
		return nil
	}

	cacheMu.Lock()
	cachedMap = loaded
	cacheMu.Unlock()

	return nil
}

// HasProduct reports whether product is a known cpemap key (after alias rewrite).
func HasProduct(product string) bool {
	_, ok := Lookup(product)

	return ok
}
