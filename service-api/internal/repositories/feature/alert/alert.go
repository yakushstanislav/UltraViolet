// Package alert stores alert rules and their firing events.
package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Rule is one row from uv_alert_rule.
type Rule struct {
	ID            uint64
	Name          string
	SavedSearchID sql.NullInt64
	Query         map[string]any
	Channel       string
	Destination   string
	CooldownSec   int32
	Enabled       bool
	LastFiredAt   sql.NullTime
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Event is one row from uv_alert_event.
type Event struct {
	ID        uint64
	RuleID    uint64
	HitsCount int
	Payload   map[string]any
	CreatedAt time.Time
}

// Repository is the storage contract for alert rules and events.
type Repository interface {
	CreateRule(ctx context.Context, input *Rule) (uint64, error)
	GetRules(ctx context.Context, limit, offset uint64) ([]*Rule, uint64, error)
	GetAllRules(ctx context.Context, limit, offset uint64) ([]*Rule, uint64, error)
	DeleteRule(ctx context.Context, id uint64) error
	SetRuleEnabled(ctx context.Context, id uint64, enabled bool) error
	CountActiveRules(ctx context.Context) (uint64, error)
	CountEventsSince(ctx context.Context, since time.Time) (uint64, error)
	RegisterEvent(ctx context.Context, ruleID uint64, hits int, payload map[string]any) error
	GetEvents(ctx context.Context, limit, offset uint64) ([]*Event, uint64, error)
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

// CreateRule inserts a new alert rule and returns its id.
func (p *PostgreSQL) CreateRule(ctx context.Context, input *Rule) (uint64, error) {
	payload, err := json.Marshal(input.Query)
	if err != nil {
		return 0, fmt.Errorf("can't marshal alert rule query: %w", err)
	}

	now := time.Now().UTC()

	query, args, err := sq.Insert("uv_alert_rule").
		Columns("name", "saved_search_id", "query", "channel", "destination", "cooldown_sec", "enabled", "created_at", "updated_at").
		Values(input.Name, input.SavedSearchID, payload, input.Channel, input.Destination, input.CooldownSec, input.Enabled, now, now).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build create alert rule query: %w", err)
	}

	var id uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't create alert rule: %w", pgkit.Handle(err))
	}

	return id, nil
}

// GetRules returns a paginated list of enabled alert rules and the total count.
func (p *PostgreSQL) GetRules(ctx context.Context, limit, offset uint64) ([]*Rule, uint64, error) {
	countSQL, countArgs, err := sq.Select("COUNT(*)").
		From("uv_alert_rule").
		Where(squirrel.Eq{"enabled": true}).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count alert rules query: %w", err)
	}

	var total uint64

	err = p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("can't count alert rules: %w", pgkit.Handle(err))
	}

	query, args, err := sq.Select(
		"id", "name", "saved_search_id", "query", "channel", "destination",
		"cooldown_sec", "enabled", "last_fired_at", "created_at", "updated_at",
	).
		From("uv_alert_rule").
		Where(squirrel.Eq{"enabled": true}).
		OrderBy("id").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list alert rules query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list alert rules: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*Rule

	for rows.Next() {
		item := &Rule{}

		var raw []byte

		if err := rows.Scan(
			&item.ID, &item.Name, &item.SavedSearchID, &raw,
			&item.Channel, &item.Destination, &item.CooldownSec,
			&item.Enabled, &item.LastFiredAt, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("can't scan alert rule: %w", pgkit.Handle(err))
		}

		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &item.Query); err != nil {
				return nil, 0, fmt.Errorf("can't unmarshal alert rule query: %w", err)
			}
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate alert rules: %w", err)
	}

	return out, total, nil
}

// CountActiveRules returns the number of enabled alert rules.
func (p *PostgreSQL) CountActiveRules(ctx context.Context) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").
		From("uv_alert_rule").
		Where(squirrel.Eq{"enabled": true}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count active alert rules query: %w", err)
	}

	var n uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count active alert rules: %w", pgkit.Handle(err))
	}

	return n, nil
}

// CountEventsSince returns the number of alert events created on or after since.
func (p *PostgreSQL) CountEventsSince(ctx context.Context, since time.Time) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").
		From("uv_alert_event").
		Where("created_at >= ?", since).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count alert events query: %w", err)
	}

	var n uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count alert events since: %w", pgkit.Handle(err))
	}

	return n, nil
}

// GetAllRules lists all rules (enabled + disabled).
func (p *PostgreSQL) GetAllRules(ctx context.Context, limit, offset uint64) ([]*Rule, uint64, error) {
	countSQL, countArgs, err := sq.Select("COUNT(*)").From("uv_alert_rule").ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count all alert rules query: %w", err)
	}

	var total uint64

	err = p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("can't count all alert rules: %w", pgkit.Handle(err))
	}

	query, args, err := sq.Select(
		"id", "name", "saved_search_id", "query", "channel", "destination",
		"cooldown_sec", "enabled", "last_fired_at", "created_at", "updated_at",
	).
		From("uv_alert_rule").
		OrderBy("id DESC").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list all alert rules query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list all alert rules: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*Rule

	for rows.Next() {
		item := &Rule{}

		var raw []byte

		if err := rows.Scan(
			&item.ID, &item.Name, &item.SavedSearchID, &raw,
			&item.Channel, &item.Destination, &item.CooldownSec,
			&item.Enabled, &item.LastFiredAt, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("can't scan alert rule: %w", pgkit.Handle(err))
		}

		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &item.Query); err != nil {
				return nil, 0, fmt.Errorf("can't unmarshal alert rule query: %w", err)
			}
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate alert rules: %w", err)
	}

	return out, total, nil
}

// DeleteRule removes an alert rule. Returns pgkit.ErrNoRows when no rule
// matched so callers can map to a 404 instead of silently 204'ing on stale ids.
func (p *PostgreSQL) DeleteRule(ctx context.Context, id uint64) error {
	query, args, err := sq.Delete("uv_alert_rule").Where(squirrel.Eq{"id": id}).ToSql()
	if err != nil {
		return fmt.Errorf("can't build delete alert rule query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't delete alert rule: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return pgkit.ErrNoRows
	}

	return nil
}

// SetRuleEnabled toggles the enabled flag for a rule. Returns pgkit.ErrNoRows
// when no rule matched so the API can surface a real 404 instead of pretending
// the toggle succeeded against thin air.
func (p *PostgreSQL) SetRuleEnabled(ctx context.Context, id uint64, enabled bool) error {
	query, args, err := sq.Update("uv_alert_rule").
		Set("enabled", enabled).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update alert rule enabled query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't toggle alert rule: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return pgkit.ErrNoRows
	}

	return nil
}

// GetEvents returns a paginated newest-first list of alert events.
func (p *PostgreSQL) GetEvents(ctx context.Context, limit, offset uint64) ([]*Event, uint64, error) {
	countSQL, countArgs, err := sq.Select("COUNT(*)").From("uv_alert_event").ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count alert events query: %w", err)
	}

	var total uint64

	if scanErr := p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total); scanErr != nil {
		return nil, 0, fmt.Errorf("can't count alert events: %w", pgkit.Handle(scanErr))
	}

	query, args, err := sq.Select(
		"id", "alert_rule_id", "hits_count", "payload", "created_at",
	).
		From("uv_alert_event").
		OrderBy("id DESC").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list alert events query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list alert events: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*Event

	for rows.Next() {
		item := &Event{}

		var raw []byte

		if err := rows.Scan(&item.ID, &item.RuleID, &item.HitsCount, &raw, &item.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("can't scan alert event: %w", pgkit.Handle(err))
		}

		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &item.Payload); err != nil {
				return nil, 0, fmt.Errorf("can't unmarshal alert event payload: %w", err)
			}
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate alert events: %w", err)
	}

	return out, total, nil
}

// ErrCooldownActive is returned by RegisterEvent when another worker has
// already fired the same rule inside its cooldown window. Callers should
// treat it as a benign no-op (the rule fired, just not by us).
var ErrCooldownActive = errors.New("alert rule still in cooldown")

// RegisterEvent records a rule firing and updates the rule's last_fired_at
// timestamp. It re-checks last_fired_at against cooldown_sec under SELECT
// FOR UPDATE so two concurrent worker pods cannot both fire the same rule
// inside one cooldown window. When the cooldown is still active the call
// returns ErrCooldownActive without inserting an event.
func (p *PostgreSQL) RegisterEvent(ctx context.Context, ruleID uint64, hits int, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("can't marshal alert event payload: %w", err)
	}

	now := time.Now().UTC()

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can't begin alert event tx: %w", pgkit.Handle(err))
	}

	defer func() { _ = tx.Rollback(ctx) }()

	lockSQL, lockArgs, lockErr := sq.Select("cooldown_sec", "last_fired_at").
		From("uv_alert_rule").
		Where(squirrel.Eq{"id": ruleID}).
		Suffix("FOR UPDATE").
		ToSql()
	if lockErr != nil {
		return fmt.Errorf("can't build lock alert rule query: %w", lockErr)
	}

	var (
		cooldownSec int32
		lastFired   sql.NullTime
	)

	if scanErr := tx.QueryRow(ctx, lockSQL, lockArgs...).Scan(&cooldownSec, &lastFired); scanErr != nil {
		return fmt.Errorf("can't load alert rule for cooldown check: %w", pgkit.Handle(scanErr))
	}

	if lastFired.Valid && cooldownSec > 0 {
		cooldownEnd := lastFired.Time.Add(time.Duration(cooldownSec) * time.Second)
		if now.Before(cooldownEnd) {
			return ErrCooldownActive
		}
	}

	insertSQL, insertArgs, err := sq.Insert("uv_alert_event").
		Columns("alert_rule_id", "hits_count", "payload", "created_at").
		Values(ruleID, hits, raw, now).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build insert alert event query: %w", err)
	}

	_, err = tx.Exec(ctx, insertSQL, insertArgs...)
	if err != nil {
		return fmt.Errorf("can't insert alert event: %w", pgkit.Handle(err))
	}

	updateSQL, updateArgs, err := sq.Update("uv_alert_rule").
		Set("last_fired_at", now).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": ruleID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update alert rule query: %w", err)
	}

	if _, err := tx.Exec(ctx, updateSQL, updateArgs...); err != nil {
		return fmt.Errorf("can't update alert rule: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("can't commit alert event tx: %w", pgkit.Handle(err))
	}

	return nil
}
