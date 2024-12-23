package service

import (
	"context"
	"database/sql"

	"github.com/daocloud/crproxy/manager/dao"
	"github.com/daocloud/crproxy/manager/model"
)

type RegistryService struct {
	db          *sql.DB
	registryDao *dao.Registry
}

func NewRegistryService(db *sql.DB, registryDao *dao.Registry) *RegistryService {
	return &RegistryService{
		db:          db,
		registryDao: registryDao,
	}
}

func (s *RegistryService) Create(ctx context.Context, registry model.Registry) (int64, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.registryDao.Create(ctx, registry)
}

func (s *RegistryService) GetByID(ctx context.Context, registryID, userID int64) (model.Registry, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.registryDao.GetByID(ctx, registryID, userID)
}

func (s *RegistryService) GetByUserID(ctx context.Context, userID int64) ([]model.Registry, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.registryDao.GetByUserID(ctx, userID)
}

func (s *RegistryService) GetByDomain(ctx context.Context, domain string) (model.Registry, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.registryDao.GetByDomain(ctx, domain)
}

func (s *RegistryService) Delete(ctx context.Context, registryID, userID int64) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.registryDao.DeleteByID(ctx, registryID, userID)
}
