package dao

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/daocloud/crproxy/manager/model"
)

type User struct{}

func NewUser() *User {
	return &User{}
}

const userTableSQL = `
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    nickname VARCHAR(255) NOT NULL,
    create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    delete_at TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=10000 CHARSET=utf8mb4;
`

func (c *User) InitTable(ctx context.Context) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, userTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	return nil
}

const createSQL = `
INSERT INTO users (nickname) VALUES (?)
`

func (c *User) Create(ctx context.Context, u model.User) (int64, error) {
	db := GetDB(ctx)
	result, err := db.ExecContext(ctx, createSQL, u.Nickname)
	if err != nil {
		return 0, fmt.Errorf("failed to create user: %w", err)
	}

	return result.LastInsertId()
}

const getUserSQL = `
SELECT id, nickname FROM users WHERE id = ?
`

func (c *User) GetByID(ctx context.Context, id int64) (model.User, error) {
	db := GetDB(ctx)
	var u model.User

	err := db.QueryRowContext(ctx, getUserSQL, id).Scan(&u.UserID, &u.Nickname)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, fmt.Errorf("user not found: %w", err)
		}
		return model.User{}, fmt.Errorf("failed to get user: %w", err)
	}
	return u, nil
}

const updateNicknameSQL = `
UPDATE users SET nickname = ? WHERE id = ?
`

func (c *User) UpdateNickname(ctx context.Context, id int64, nickname string) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, updateNicknameSQL, nickname, id)
	if err != nil {
		return fmt.Errorf("failed to update nickname: %w", err)
	}
	return nil
}
