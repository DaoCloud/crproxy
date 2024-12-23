package dao

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/daocloud/crproxy/manager/model"
)

type Registry struct{}

func NewRegistry() *Registry {
	return &Registry{}
}

const registryTableSQL = `
CREATE TABLE IF NOT EXISTS registries (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    domain VARCHAR(255) NOT NULL,
	data JSON NOT NULL,
    create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    delete_at TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=10000 CHARSET=utf8mb4;
`

func (r *Registry) InitTable(ctx context.Context) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, registryTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create registries table: %w", err)
	}
	return nil
}

const createRegistrySQL = `
INSERT INTO registries (user_id, domain, data) VALUES (?, ?, ?)
`

func (r *Registry) Create(ctx context.Context, registry model.Registry) (int64, error) {
	db := GetDB(ctx)
	result, err := db.ExecContext(ctx, createRegistrySQL, registry.UserID, registry.Domain, registry.Data)
	if err != nil {
		return 0, fmt.Errorf("failed to create registry: %w", err)
	}

	return result.LastInsertId()
}

const getRegistryByIDSQL = `
SELECT id, user_id, domain, data FROM registries WHERE id = ? AND user_id = ? AND delete_at IS NULL
`

func (r *Registry) GetByID(ctx context.Context, registryID, userID int64) (model.Registry, error) {
	db := GetDB(ctx)
	var registry model.Registry
	err := db.QueryRowContext(ctx, getRegistryByIDSQL, registryID, userID).Scan(&registry.RegistryID, &registry.UserID, &registry.Domain, &registry.Data)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Registry{}, fmt.Errorf("registry not found: %w", err)
		}
		return model.Registry{}, fmt.Errorf("failed to get registry: %w", err)
	}
	return registry, nil
}

const getRegistriesByUserIDSQL = `
SELECT id, user_id, domain, data FROM registries WHERE user_id = ? AND delete_at IS NULL
`

func (r *Registry) GetByUserID(ctx context.Context, userID int64) ([]model.Registry, error) {
	db := GetDB(ctx)
	rows, err := db.QueryContext(ctx, getRegistriesByUserIDSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get registries by user ID: %w", err)
	}
	defer rows.Close()

	var registries []model.Registry
	for rows.Next() {
		var registry model.Registry
		if err := rows.Scan(&registry.RegistryID, &registry.UserID, &registry.Domain, &registry.Data); err != nil {
			return nil, fmt.Errorf("failed to scan registry: %w", err)
		}
		registries = append(registries, registry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred during rows iteration: %w", err)
	}

	return registries, nil
}

const getRegistryByDomainSQL = `
SELECT id, user_id, domain, data FROM registries WHERE domain = ? AND delete_at IS NULL
LIMIT 1
`

func (r *Registry) GetByDomain(ctx context.Context, domain string) (model.Registry, error) {
	db := GetDB(ctx)
	var registry model.Registry
	err := db.QueryRowContext(ctx, getRegistryByDomainSQL, domain).Scan(&registry.RegistryID, &registry.UserID, &registry.Domain, &registry.Data)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Registry{}, fmt.Errorf("registry not found for domain %s: %w", domain, err)
		}
		return model.Registry{}, fmt.Errorf("failed to get registry by domain: %w", err)
	}
	return registry, nil
}

const updateRegistryByIDSQL = `
UPDATE registries SET domain = ?, data = ? WHERE id = ? AND user_id = ? AND delete_at IS NULL
`

func (r *Registry) UpdateByID(ctx context.Context, registryID, userID int64, registry model.Registry) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, updateRegistryByIDSQL, registry.Domain, registry.Data, registryID, userID)
	if err != nil {
		return fmt.Errorf("failed to update registry: %w", err)
	}
	return nil
}

const deleteRegistryByIDSQL = `
DELETE FROM registries WHERE id = ? AND user_id = ? AND delete_at IS NULL
`

func (r *Registry) DeleteByID(ctx context.Context, registryID, userID int64) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, deleteRegistryByIDSQL, registryID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete registry: %w", err)
	}
	return nil
}
