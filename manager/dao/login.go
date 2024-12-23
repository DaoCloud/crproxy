package dao

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/daocloud/crproxy/manager/model"
)

type Login struct{}

func NewLogin() *Login {
	return &Login{}
}

const loginTableSQL = `
CREATE TABLE IF NOT EXISTS logins (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    type VARCHAR(50) NOT NULL,
    account VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    delete_at TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=10000 CHARSET=utf8mb4;
`

func (l *Login) InitTable(ctx context.Context) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, loginTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create logins table: %w", err)
	}
	return nil
}

const createLoginSQL = `
INSERT INTO logins (user_id, type, account, password) VALUES (?, ?, ?, ?)
`

func (l *Login) Create(ctx context.Context, login model.Login) (int64, error) {
	db := GetDB(ctx)
	result, err := db.ExecContext(ctx, createLoginSQL, login.UserID, login.Type, login.Account, login.Password)
	if err != nil {
		return 0, fmt.Errorf("failed to create login: %w", err)
	}

	return result.LastInsertId()
}

const getLoginByIDSQL = `
SELECT id, user_id, type, account, password FROM logins WHERE id = ? AND delete_at IS NULL
`

func (l *Login) GetByID(ctx context.Context, id int64) (model.Login, error) {
	db := GetDB(ctx)
	var login model.Login
	err := db.QueryRowContext(ctx, getLoginByIDSQL, id).Scan(&login.LoginID, &login.UserID, &login.Type, &login.Account, &login.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Login{}, fmt.Errorf("login not found: %w", err)
		}
		return model.Login{}, fmt.Errorf("failed to get login: %w", err)
	}
	return login, nil
}

const getLoginByAccountSQL = `
SELECT id, user_id, type, account, password FROM logins WHERE account = ? AND delete_at IS NULL
`

func (l *Login) GetByAccount(ctx context.Context, account string) (model.Login, error) {
	db := GetDB(ctx)
	var login model.Login
	err := db.QueryRowContext(ctx, getLoginByAccountSQL, account).Scan(&login.LoginID, &login.UserID, &login.Type, &login.Account, &login.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Login{}, fmt.Errorf("login not found for account %s: %w", account, err)
		}
		return model.Login{}, fmt.Errorf("failed to get login by account: %w", err)
	}
	return login, nil
}

const deleteLoginByID = `
UPDATE logins SET delete_at = NOW() WHERE id = ?
`

func (l *Login) DeleteByID(ctx context.Context, id int64) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, deleteLoginByID, id)
	if err != nil {
		return fmt.Errorf("failed to delete login: %w", err)
	}
	return nil
}

const updatePasswordSQL = `
UPDATE logins SET password = ? WHERE id = ? AND delete_at IS NULL
`

func (l *Login) UpdatePassword(ctx context.Context, id int64, newPassword string) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, updatePasswordSQL, newPassword, id)
	if err != nil {
		return fmt.Errorf("failed to update password for login id %d: %w", id, err)
	}
	return nil
}
