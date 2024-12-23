package dao

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/daocloud/crproxy/manager/model"
)

type Token struct{}

func NewToken() *Token {
	return &Token{}
}

const tokenTableSQL = `
CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    account VARCHAR(255) NOT NULL,
	password VARCHAR(255) NOT NULL,
	data JSON NOT NULL,
    create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    delete_at TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=10000 CHARSET=utf8mb4;
`

func (t *Token) InitTable(ctx context.Context) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, tokenTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create tokens table: %w", err)
	}
	return nil
}

const createTokenSQL = `
INSERT INTO tokens (user_id, account, password, data) VALUES (?, ?, ?, ?)
`

func (t *Token) Create(ctx context.Context, token model.Token) (int64, error) {
	db := GetDB(ctx)
	result, err := db.ExecContext(ctx, createTokenSQL, token.UserID, token.Account, token.Password, token.Data)
	if err != nil {
		return 0, fmt.Errorf("failed to create token: %w", err)
	}

	return result.LastInsertId()
}

const getTokenByIDSQL = `
SELECT id, user_id, account, data FROM tokens WHERE id = ? AND user_id = ? AND delete_at IS NULL
`

func (t *Token) GetByID(ctx context.Context, tokenID, userID int64) (model.Token, error) {
	db := GetDB(ctx)
	var token model.Token
	err := db.QueryRowContext(ctx, getTokenByIDSQL, tokenID, userID).Scan(&token.TokenID, &token.UserID, &token.Account, &token.Data)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Token{}, fmt.Errorf("token not found: %w", err)
		}
		return model.Token{}, fmt.Errorf("failed to get token: %w", err)
	}
	return token, nil
}

const getTokensByUserIDSQL = `
SELECT id, user_id, account, data FROM tokens WHERE user_id = ? AND delete_at IS NULL
`

func (t *Token) GetByUserID(ctx context.Context, userID int64) ([]model.Token, error) {
	db := GetDB(ctx)
	rows, err := db.QueryContext(ctx, getTokensByUserIDSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tokens by user ID: %w", err)
	}
	defer rows.Close()

	var tokens []model.Token
	for rows.Next() {
		var token model.Token
		if err := rows.Scan(&token.TokenID, &token.UserID, &token.Account, &token.Data); err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred during rows iteration: %w", err)
	}

	return tokens, nil
}

const getTokenSQL = `
SELECT id, user_id, account, data FROM tokens WHERE user_id = ? AND account = ? AND password = ? AND delete_at IS NULL
`

func (t *Token) GetByAccount(ctx context.Context, userID int64, account, password string) (model.Token, error) {
	db := GetDB(ctx)
	var token model.Token
	err := db.QueryRowContext(ctx, getTokenSQL, userID, account, password).Scan(&token.TokenID, &token.UserID, &token.Account, &token.Data)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Token{}, fmt.Errorf("token not found: %w", err)
		}
		return model.Token{}, fmt.Errorf("failed to get token: %w", err)
	}
	return token, nil
}

const deleteTokenByIDSQL = `
UPDATE tokens SET delete_at = NOW() WHERE id = ? AND user_id = ? AND delete_at IS NULL
`

func (t *Token) DeleteByID(ctx context.Context, tokenID, userID int64) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, deleteTokenByIDSQL, tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}
	return nil
}
