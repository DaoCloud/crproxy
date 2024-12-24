package service

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/daocloud/crproxy/internal/slices"
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

func (s *RegistryService) UpdateByID(ctx context.Context, registryID, userID int64, registry model.Registry) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.registryDao.UpdateByID(ctx, registryID, userID, registry)
}

func (s *RegistryService) DeleteByID(ctx context.Context, registryID, userID int64) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.registryDao.DeleteByID(ctx, registryID, userID)
}

func (s *RegistryService) UpdateAllowImages(ctx context.Context, userID int64, allows []string, blockMessage string) (retErr error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	ctx = dao.WithDB(ctx, tx)

	registrys, err := s.registryDao.GetByUserID(ctx, userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	sort.Strings(allows)

	for _, registry := range registrys {
		if registry.Data.AllowPrefix {
			registry.Data.Allowlist = allows
		} else if registry.Data.Source != "" {
			s := registry.Data.Source + "/"
			registry.Data.Allowlist = slices.Filter(allows, func(image string) bool {
				return strings.HasPrefix(image, s)
			})
			if slices.Contains(registry.Data.Allowlist, registry.Data.Source+"/**") {
				registry.Data.EnableAllowlist = false
			}
		} else {
			continue
		}

		registry.Data.EnableAllowlist = true
		if blockMessage != "" {
			registry.Data.AllowlisBlockMessage = blockMessage
		}

		err = s.registryDao.UpdateByID(ctx, registry.RegistryID, userID, registry)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (s *RegistryService) UpdateIPData(ctx context.Context, userID int64, ips []string, attr model.TokenAttr) (retErr error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	ctx = dao.WithDB(ctx, tx)

	registrys, err := s.registryDao.GetByUserID(ctx, userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, registry := range registrys {
		if registry.Data.SpecialIPs == nil {
			registry.Data.SpecialIPs = map[string]model.TokenAttr{}
		}
		for _, ip := range ips {
			registry.Data.SpecialIPs[ip] = attr
		}

		err = s.registryDao.UpdateByID(ctx, registry.RegistryID, userID, registry)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (s *RegistryService) UpdateAnonymousData(ctx context.Context, userID int64, attr model.TokenAttr) (retErr error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	ctx = dao.WithDB(ctx, tx)

	registrys, err := s.registryDao.GetByUserID(ctx, userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, registry := range registrys {
		registry.Data.Anonymous = attr
		err = s.registryDao.UpdateByID(ctx, registry.RegistryID, userID, registry)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}
