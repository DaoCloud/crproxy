package manager

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/daocloud/crproxy/internal/cache"
	"github.com/daocloud/crproxy/internal/format"
	"github.com/daocloud/crproxy/manager/controller"
	"github.com/daocloud/crproxy/manager/dao"
	"github.com/daocloud/crproxy/manager/model"
	"github.com/daocloud/crproxy/manager/service"
	"github.com/daocloud/crproxy/token"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-openapi/spec"
	"github.com/wzshiming/hostmatcher"
)

type Manager struct {
	key        *rsa.PrivateKey
	adminToken string
	db         *sql.DB

	UserDAO     *dao.User
	LoginDAO    *dao.Login
	TokenDAO    *dao.Token
	RegistryDAO *dao.Registry

	UserService        *service.UserService
	UserController     *controller.UserController
	TokenService       *service.TokenService
	TokenController    *controller.TokenController
	RegistryService    *service.RegistryService
	RegistryController *controller.RegistryController

	tokenCache    *cache.Cache[userKey, responseItem[model.Token]]
	registryCache *cache.Cache[string, responseItem[registryCache]]
	cacheTTL      time.Duration
}

func NewManager(key *rsa.PrivateKey, adminToken string, db *sql.DB, cacheTTL time.Duration) *Manager {
	m := &Manager{
		key:           key,
		adminToken:    adminToken,
		db:            db,
		cacheTTL:      cacheTTL,
		tokenCache:    cache.NewCache[userKey, responseItem[model.Token]](),
		registryCache: cache.NewCache[string, responseItem[registryCache]](),
	}
	return m
}

func (m *Manager) InitTable(ctx context.Context) {
	ctx = dao.WithDB(ctx, m.db)
	m.UserDAO.InitTable(ctx)
	m.LoginDAO.InitTable(ctx)
	m.TokenDAO.InitTable(ctx)
	m.RegistryDAO.InitTable(ctx)
}

func (m *Manager) Register(container *restful.Container) {
	m.UserDAO = dao.NewUser()
	m.LoginDAO = dao.NewLogin()
	m.TokenDAO = dao.NewToken()
	m.RegistryDAO = dao.NewRegistry()

	m.UserService = service.NewUserService(m.db, m.UserDAO, m.LoginDAO)
	m.UserController = controller.NewUserController(m.key, m.adminToken, m.UserService)
	m.TokenService = service.NewTokenService(m.db, m.TokenDAO)
	m.TokenController = controller.NewTokenController(m.key, m.TokenService)
	m.RegistryService = service.NewRegistryService(m.db, m.RegistryDAO)
	m.RegistryController = controller.NewRegistryController(m.key, m.RegistryService)

	ws := new(restful.WebService)
	ws.Path("/apis/v1/")
	m.UserController.RegisterRoutes(ws)
	m.TokenController.RegisterRoutes(ws)
	m.RegistryController.RegisterRoutes(ws)

	container.Add(ws)

	config := restfulspec.Config{
		WebServices: []*restful.WebService{ws},
		APIPath:     "/swagger.json",
		PostBuildSwaggerObjectHandler: func(s *spec.Swagger) {
			s.Info = &spec.Info{}
			s.Info.Title = "CRProxy Manager"
			s.Schemes = []string{"http", "https"}
			s.SecurityDefinitions = spec.SecurityDefinitions{
				"BearerHeader": {
					SecuritySchemeProps: spec.SecuritySchemeProps{
						Description: `Enter the token with the "Bearer token", and the token get by /users/login`,
						Type:        "apiKey",
						In:          "header",
						Name:        "Authorization",
					},
				},
			}
			s.Security = []map[string][]string{
				{"BearerHeader": []string{}},
			}
		},
	}

	container.Add(restfulspec.NewOpenAPIService(config))
}

func (m *Manager) getRegistry(ctx context.Context, t *token.Token) (registryCache, error) {
	up := t.Service

	m.registryCache.Evict()

	cached, found := m.registryCache.Get(up)
	if found {
		return cached.attr, cached.err
	}

	registry, err := m.RegistryService.GetByDomain(ctx, t.Service)
	if err != nil {
		m.registryCache.Set(up, responseItem[registryCache]{err: err}, m.cacheTTL)
		return registryCache{}, err
	}

	rc := registryCache{
		Registry: registry,
	}

	if len(registry.Data.AllowImages) != 0 {
		rc.ImagesMatcher = hostmatcher.NewMatcher(registry.Data.AllowImages)
	}

	m.registryCache.Set(up, responseItem[registryCache]{attr: rc}, m.cacheTTL)
	return rc, nil
}

func (m *Manager) getToken(ctx context.Context, userinfo *url.Userinfo, t *token.Token, registry registryCache, image string) (model.Token, error) {

	if userinfo == nil {
		if len(registry.Registry.Data.SpecialIPs) != 0 {
			tt, ok := registry.Registry.Data.SpecialIPs[t.IP]
			if ok {
				return model.Token{
					UserID: registry.Registry.UserID,
					Data:   tt,
				}, nil
			}
		}

		if !registry.Registry.Data.AllowAnonymous {
			return model.Token{}, fmt.Errorf("anonymous access is not allowed")
		}

		if !registry.Registry.Data.Anonymous.NoAllowlist && registry.ImagesMatcher != nil {
			if !registry.ImagesMatcher.Match(image) {
				return model.Token{}, fmt.Errorf("image %q is not allowed", image)
			}
		}

		return model.Token{
			UserID: registry.Registry.UserID,
			Data:   registry.Registry.Data.Anonymous,
		}, nil
	}

	pwd, _ := userinfo.Password()
	username := userinfo.Username()

	up := userKey{
		UserID:        registry.Registry.UserID,
		TokenUser:     username,
		TokenPassword: pwd,
	}

	m.tokenCache.Evict()

	cached, found := m.tokenCache.Get(up)
	if found {
		return cached.attr, cached.err
	}
	tt, err := m.TokenService.GetByAccount(ctx, up.UserID, up.TokenUser, up.TokenPassword)
	if err != nil {
		m.tokenCache.Set(up, responseItem[model.Token]{err: err}, m.cacheTTL)
		return model.Token{}, err
	}

	if !tt.Data.NoAllowlist && registry.ImagesMatcher != nil {
		if !registry.ImagesMatcher.Match(image) {
			return model.Token{}, fmt.Errorf("image %q is not allowed", image)
		}
	}

	m.tokenCache.Set(up, responseItem[model.Token]{attr: tt}, m.cacheTTL)

	return tt, nil
}

func (m *Manager) GetTokenWithUser(ctx context.Context, userinfo *url.Userinfo, t *token.Token) (token.Attribute, error) {
	registry, err := m.getRegistry(ctx, t)
	if err != nil {
		return token.Attribute{}, err
	}

	var (
		host  string
		image string
	)

	hostAndImage := strings.SplitN(t.Image, "/", 2)
	if len(hostAndImage) > 1 {
		if registry.Registry.Data.AllowPrefix {
			if format.IsDomainName(hostAndImage[0]) && strings.Contains(host, ".") {
				host = hostAndImage[0]
				image = hostAndImage[1]
			} else if registry.Registry.Data.Source == "" {
				return token.Attribute{}, fmt.Errorf("no domain provide")
			} else {
				host = registry.Registry.Data.Source
				image = t.Image
			}
		} else {
			if format.IsDomainName(hostAndImage[0]) && strings.Contains(host, ".") {
				return token.Attribute{}, fmt.Errorf("domain perfix is not allowed")
			} else if registry.Registry.Data.Source == "" {
				return token.Attribute{}, fmt.Errorf("no domain provide")
			} else {
				host = registry.Registry.Data.Source
				image = t.Image
			}
		}
	}

	tt, err := m.getToken(ctx, userinfo, t, registry, host+"/"+image)
	if err != nil {
		return token.Attribute{}, err
	}

	attr := token.Attribute{
		UserID:     tt.UserID,
		TokenID:    tt.TokenID,
		RegistryID: registry.Registry.RegistryID,

		NoRateLimit:        tt.Data.NoRateLimit,
		RateLimitPerSecond: tt.Data.RateLimitPerSecond,

		NoAllowlist:   tt.Data.NoAllowlist,
		NoBlock:       tt.Data.NoBlock,
		AllowTagsList: tt.Data.AllowTagsList,

		Host:  host,
		Image: image,
	}
	return attr, nil
}

type userKey struct {
	UserID        int64
	TokenUser     string
	TokenPassword string
}

type responseItem[T any] struct {
	err  error
	attr T
}

type registryCache struct {
	Registry      model.Registry
	ImagesMatcher hostmatcher.Matcher
}
