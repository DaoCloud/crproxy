package service

import (
	"context"
	"database/sql"

	"github.com/daocloud/crproxy/manager/dao"
	"github.com/daocloud/crproxy/manager/model"
)

type TokenService struct {
	db       *sql.DB
	tokenDao *dao.Token
}

func NewTokenService(db *sql.DB, tokenDao *dao.Token) *TokenService {
	return &TokenService{
		db:       db,
		tokenDao: tokenDao,
	}
}

func (s *TokenService) Create(ctx context.Context, token model.Token) (int64, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.tokenDao.Create(ctx, token)
}

func (s *TokenService) GetByAccount(ctx context.Context, userID int64, account, password string) (model.Token, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.tokenDao.GetByAccount(ctx, userID, account, password)
}

func (s *TokenService) Get(ctx context.Context, tokenID, userID int64) (model.Token, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.tokenDao.GetByID(ctx, tokenID, userID)
}

func (s *TokenService) Delete(ctx context.Context, tokenID, userID int64) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.tokenDao.DeleteByID(ctx, tokenID, userID)
}

func (s *TokenService) GetByUserID(ctx context.Context, userID int64) ([]model.Token, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.tokenDao.GetByUserID(ctx, userID)
}
