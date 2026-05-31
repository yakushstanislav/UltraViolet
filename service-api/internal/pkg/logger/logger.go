package logger

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// Config holds logger settings.
type Config struct {
	Name  string `env:"LOGGER_NAME"  env-required:"true"`
	Debug bool   `env:"LOGGER_DEBUG" env-required:"true"`
}

type loggerContextKey struct{}

// NewLogger builds a sugared zap logger from config.
func NewLogger(config *Config) (*zap.SugaredLogger, error) {
	var zapConfig zap.Config

	if config.Debug {
		zapConfig = zap.NewDevelopmentConfig()
	} else {
		zapConfig = zap.NewProductionConfig()
	}

	zapConfig.EncoderConfig.CallerKey = ""

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("can't build logger: %w", err)
	}

	logger = logger.With(zap.String("service", config.Name))

	return logger.Sugar(), nil
}

// PackContext attaches the logger to the context.
func PackContext(ctx context.Context, logger *zap.SugaredLogger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, logger)
}

// UnpackContext returns the logger from context, or a no-op logger if none is set.
func UnpackContext(ctx context.Context) *zap.SugaredLogger {
	logger, ok := ctx.Value(loggerContextKey{}).(*zap.SugaredLogger)
	if !ok {
		return zap.NewNop().Sugar()
	}

	return logger
}
