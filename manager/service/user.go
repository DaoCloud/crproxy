package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/daocloud/crproxy/manager/dao"
	"github.com/daocloud/crproxy/manager/model"
)

type UserService struct {
	db       *sql.DB
	userDao  *dao.User
	loginDao *dao.Login
}

func NewUserService(db *sql.DB, userDao *dao.User, loginDao *dao.Login) *UserService {
	return &UserService{
		db:       db,
		userDao:  userDao,
		loginDao: loginDao,
	}
}

func (s *UserService) Create(ctx context.Context, nickname, account, password string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}

	ctx = dao.WithDB(ctx, tx)

	_, err = s.loginDao.GetByAccount(ctx, account)
	if err == nil {
		return 0, fmt.Errorf("account already exists")
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("failed to check account: %w", err)
	}

	user := model.User{Nickname: nickname}
	userID, err := s.userDao.Create(ctx, user)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	login := model.Login{
		UserID:   userID,
		Account:  account,
		Password: password,
	}
	_, err = s.loginDao.Create(ctx, login)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (s *UserService) GetByID(ctx context.Context, id int64) (model.User, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.userDao.GetByID(ctx, id)
}

func (s *UserService) GetLoginByAccount(ctx context.Context, account string) (model.Login, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.loginDao.GetByAccount(ctx, account)
}

func (s *UserService) UpdateNickname(ctx context.Context, id int64, nickname string) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.userDao.UpdateNickname(ctx, id, nickname)
}
