// Package nullable converts between database/sql null types, plain Go types
// and pointer-based "optional" representations used in DTOs.
package nullable

import (
	"database/sql"
	"time"
)

// String returns "" when not valid.
func String(value sql.NullString) string {
	if !value.Valid {
		return ""
	}

	return value.String
}

// TimeRFC3339 returns "" when not valid.
func TimeRFC3339(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}

	return value.Time.UTC().Format(time.RFC3339)
}

// NullString builds a NullString that is invalid for empty input.
func NullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

// NullFloat64 builds a NullFloat64.
func NullFloat64(value float64, valid bool) sql.NullFloat64 {
	return sql.NullFloat64{Float64: value, Valid: valid}
}

// NullInt32 builds a NullInt32.
func NullInt32(value int32, valid bool) sql.NullInt32 {
	return sql.NullInt32{Int32: value, Valid: valid}
}

// NullInt64 builds a NullInt64.
func NullInt64(value int64, valid bool) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: valid}
}

// NullTime returns invalid for zero time.
func NullTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: !value.IsZero()}
}

// NullBool returns invalid for nil pointer.
func NullBool(value *bool) sql.NullBool {
	if value == nil {
		return sql.NullBool{}
	}

	return sql.NullBool{Bool: *value, Valid: true}
}

// StringPtr returns nil for empty input.
func StringPtr(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

// Float64Ptr returns nil when valid is false.
func Float64Ptr(value float64, valid bool) *float64 {
	if !valid {
		return nil
	}

	return &value
}

// Int64Ptr returns nil when valid is false.
func Int64Ptr(value int64, valid bool) *int64 {
	if !valid {
		return nil
	}

	return &value
}

// StringValue returns "" for nil.
func StringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}
