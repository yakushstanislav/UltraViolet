package app

import (
	"context"
	"os"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cpemap"
	cpemaprepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cpemap"
)

// BootstrapCPEMap wires the DB-backed product map cache used by the matcher and
// HTTP-derived fingerprinters. Call once after migrations, before scanner work.
func BootstrapCPEMap(ctx context.Context, cpeProductMap cpemaprepository.Repository, logger *zap.SugaredLogger) {
	cpemap.Init(cpeProductMap, os.Getenv("CPEMAP_BUILTIN_ONLY") == "1")

	if err := cpemap.Reload(ctx); err != nil {
		logger.Warnw("Initial cpemap reload failed, using builtin fallback", zap.Error(err))
	}

	cpemap.StartRefresh(ctx, logger, 0)
}
