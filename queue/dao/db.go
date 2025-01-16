package dao

import (
	"context"
	"database/sql"
)

type dbCtxKey struct{}

// contextKey is a key type for storing database context values.
var contextKey = dbCtxKey{}

// WithDB returns a new context with the given database connection.
func WithDB(ctx context.Context, db DB) context.Context {
	return context.WithValue(ctx, contextKey, db)
}

// GetDB retrieves the database connection from the context.
func GetDB(ctx context.Context) DB {
	db := ctx.Value(contextKey)
	if db == nil {
		return nil
	}
	d, _ := db.(DB)
	return d
}

var (
	_ DB = (*sql.Tx)(nil)
	_ DB = (*sql.DB)(nil)
)

type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
