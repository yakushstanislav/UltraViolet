// Package alert evaluates active alert rules against the search index and
// records firing events on the queue.
package alert

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/alertchannels"
	alertrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/alert"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/search"
)

// Maximum number of active rules considered per tick. Active rule counts in
// production are tiny; we cap to keep the loop bounded.
const ruleBatchLimit = 1000

// Job evaluates active alert rules in a single Tick.
type Job struct {
	alertRepository  alertrepository.Repository
	searchRepository search.Repository
	dispatcher       *alertchannels.Dispatcher
	logger           *zap.SugaredLogger
}

// New builds a Job.
func New(alertRepository alertrepository.Repository, searchRepository search.Repository, logger *zap.SugaredLogger) *Job {
	return &Job{
		alertRepository:  alertRepository,
		searchRepository: searchRepository,
		dispatcher:       alertchannels.New(),
		logger:           logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "alert" }

// Tick implements worker.Job. Alert evaluation never reports didWork=true so
// the runner doesn't skip its idle sleep just because we tried.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	rules, total, err := j.alertRepository.GetRules(ctx, ruleBatchLimit, 0)
	if err != nil {
		return false, fmt.Errorf("can't list alert rules: %w", err)
	}

	if total > ruleBatchLimit {
		j.logger.Warnw("Alert rules exceed batch limit; later rules will not fire this tick",
			zap.Uint64("total", total),
			zap.Uint64("batch_limit", ruleBatchLimit),
		)
	}

	now := time.Now().UTC()

	for _, rule := range rules {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		if rule.LastFiredAt.Valid && rule.CooldownSec > 0 {
			cooldownEnd := rule.LastFiredAt.Time.Add(time.Duration(rule.CooldownSec) * time.Second)
			if now.Before(cooldownEnd) {
				continue
			}
		}

		params := queryFromRule(rule.Query)

		hits, _, err := j.searchRepository.Search(ctx, params)
		if err != nil {
			j.logger.Warnw("Can't evaluate alert rule search",
				zap.Uint64("rule_id", rule.ID),
				zap.Error(err),
			)

			continue
		}

		if len(hits) == 0 {
			continue
		}

		payload := map[string]any{"rule": rule.Name, "hits": len(hits)}

		if err := j.alertRepository.RegisterEvent(ctx, rule.ID, len(hits), payload); err != nil {
			if errors.Is(err, alertrepository.ErrCooldownActive) {
				continue
			}

			j.logger.Warnw("Can't register alert event",
				zap.Uint64("rule_id", rule.ID),
				zap.Error(err),
			)

			continue
		}

		j.logger.Infow("Alert fired", zap.Uint64("rule_id", rule.ID), zap.Int("hits", len(hits)))

		if rule.Channel != "" && rule.Channel != "log" && rule.Destination != "" {
			err := j.dispatcher.Send(ctx, rule.Channel, rule.Destination, alertchannels.Notification{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Hits:     len(hits),
				Query:    rule.Query,
			})
			if err != nil {
				j.logger.Warnw("Can't deliver alert notification",
					zap.Uint64("rule_id", rule.ID),
					zap.String("channel", rule.Channel),
					zap.Error(err),
				)
			}
		}
	}

	return false, nil
}

// queryFromRule maps a rule.Query JSON blob into a search.Query so alert
// evaluation honours every filter the rule was created with, not just the
// free-text q. Unknown / wrong-typed keys are skipped silently — the rule
// stays loose rather than failing the whole tick.
func queryFromRule(raw map[string]any) *search.Query {
	q := &search.Query{Limit: 10}

	if raw == nil {
		return q
	}

	if v, ok := raw["q"].(string); ok {
		q.Q = strings.TrimSpace(v)
	}

	q.Port = uint16FromAny(raw["port"])
	q.PortFrom = uint16FromAny(raw["port_from"])
	q.PortTo = uint16FromAny(raw["port_to"])

	if v, ok := raw["country"].(string); ok {
		q.Country = strings.ToUpper(strings.TrimSpace(v))
	}

	q.ASN = uint64FromAny(raw["asn"])

	if v, ok := raw["protocol"].(string); ok {
		q.Protocol = strings.TrimSpace(v)
	}

	if v, ok := raw["tls_issuer"].(string); ok {
		q.TLSIssuer = strings.TrimSpace(v)
	}

	if v, ok := raw["tls_fingerprint"].(string); ok {
		q.TLSFingerprint = strings.TrimSpace(v)
	}

	if v, ok := raw["tls_subject"].(string); ok {
		q.TLSSubject = strings.TrimSpace(v)
	}

	if v, ok := raw["tls_san"].(string); ok {
		q.TLSSAN = strings.TrimSpace(v)
	}

	if v, ok := raw["ssh"].(string); ok {
		q.SSH = strings.TrimSpace(v)
	}

	if v, ok := raw["ssh_fingerprint"].(string); ok {
		q.SSHFingerprint = strings.TrimSpace(v)
	}

	if v, ok := raw["smtp"].(string); ok {
		q.SMTP = strings.TrimSpace(v)
	}

	if v, ok := raw["dns"].(string); ok {
		q.DNS = strings.TrimSpace(v)
	}

	if v, ok := raw["q_mode"].(string); ok {
		q.QMode = strings.TrimSpace(v)
	}

	if v, ok := raw["cve_id"].(string); ok {
		q.CVEID = strings.ToUpper(strings.TrimSpace(v))
	}

	if v, ok := raw["cve_text"].(string); ok {
		q.CVEText = strings.TrimSpace(v)
	}

	if v, ok := raw["sort"].(string); ok {
		q.Sort = strings.TrimSpace(v)
	}

	if v, ok := raw["last_seen_from"].(string); ok {
		if t, parseErr := time.Parse(time.RFC3339, v); parseErr == nil {
			q.LastSeenFrom = t
		}
	}

	if v, ok := raw["last_seen_to"].(string); ok {
		if t, parseErr := time.Parse(time.RFC3339, v); parseErr == nil {
			q.LastSeenTo = t
		}
	}

	if v, ok := intPointerFromAny(raw["risk_score_min"]); ok {
		q.RiskScoreMin = v
	}

	if v, ok := intPointerFromAny(raw["risk_score_max"]); ok {
		q.RiskScoreMax = v
	}

	if v, ok := raw["has_cve"].(bool); ok {
		q.HasCVE = v
	}

	if severities := stringSliceFromAny(raw["cve_severity"]); len(severities) > 0 {
		q.CVESeverities = severities
		q.HasCVE = true
	}

	return q
}

func uint16FromAny(v any) uint16 {
	switch n := v.(type) {
	case float64:
		if n >= 0 && n <= 65535 {
			return uint16(n)
		}
	case int:
		if n >= 0 && n <= 65535 {
			return uint16(n)
		}
	case int64:
		if n >= 0 && n <= 65535 {
			return uint16(n)
		}
	}

	return 0
}

func uint64FromAny(v any) uint64 {
	switch n := v.(type) {
	case float64:
		if n >= 0 {
			return uint64(n)
		}
	case int:
		if n >= 0 {
			return uint64(n)
		}
	case int64:
		if n >= 0 {
			return uint64(n)
		}
	case uint64:
		return n
	}

	return 0
}

func intPointerFromAny(v any) (*int, bool) {
	switch n := v.(type) {
	case float64:
		i := int(n)
		return &i, true
	case int:
		return &n, true
	case int64:
		i := int(n)
		return &i, true
	}

	return nil, false
}

func stringSliceFromAny(v any) []string {
	switch s := v.(type) {
	case string:
		out := make([]string, 0, 4)

		for _, part := range strings.Split(s, ",") {
			trimmed := strings.ToUpper(strings.TrimSpace(part))
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}

		return out
	case []any:
		out := make([]string, 0, len(s))

		for _, item := range s {
			if str, ok := item.(string); ok {
				trimmed := strings.ToUpper(strings.TrimSpace(str))
				if trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}

		return out
	}

	return nil
}
