package manager

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

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
	"github.com/wzshiming/imc"
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

	tokenCache    *imc.Cache[userKey, responseItem[model.Token]]
	registryCache *imc.Cache[string, responseItem[registryCache]]
	cacheTTL      time.Duration
}

func NewManager(key *rsa.PrivateKey, adminToken string, db *sql.DB) *Manager {
	m := &Manager{
		key:           key,
		adminToken:    adminToken,
		db:            db,
		cacheTTL:      10 * time.Second,
		tokenCache:    imc.NewCache[userKey, responseItem[model.Token]](),
		registryCache: imc.NewCache[string, responseItem[registryCache]](),
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
			s.Schemes = []string{"https", "http"}
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

	m.registryCache.Evict(nil)

	cached, found := m.registryCache.Get(up)
	if found {
		return cached.attr, cached.err
	}

	registry, err := m.RegistryService.GetByDomain(ctx, t.Service)
	if err != nil {
		m.registryCache.SetWithTTL(up, responseItem[registryCache]{err: err}, m.cacheTTL)
		return registryCache{}, err
	}

	ttl := m.cacheTTL
	if registry.Data.TTLSecond > 0 {
		ttl = time.Duration(registry.Data.TTLSecond) * time.Second
	}

	rc := registryCache{
		Registry: registry,
	}

	if registry.Data.EnableAllowlist {
		rc.ImagesMatcher = hostmatcher.NewMatcher(registry.Data.Allowlist)
	}

	m.registryCache.SetWithTTL(up, responseItem[registryCache]{attr: rc}, ttl)
	return rc, nil
}

func (m *Manager) getToken(ctx context.Context, userinfo *url.Userinfo, t *token.Token, registry registryCache) (model.Token, error) {
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

	m.tokenCache.Evict(nil)

	cached, found := m.tokenCache.Get(up)
	if found {
		return cached.attr, cached.err
	}

	tok, err := m.TokenService.GetByAccount(ctx, up.UserID, up.TokenUser, up.TokenPassword)
	if err != nil {
		m.tokenCache.SetWithTTL(up, responseItem[model.Token]{err: err}, m.cacheTTL)
		return model.Token{}, err
	}

	ttl := m.cacheTTL
	if registry.Registry.Data.TTLSecond > 0 {
		ttl = time.Duration(registry.Registry.Data.TTLSecond) * time.Second
	}

	m.tokenCache.SetWithTTL(up, responseItem[model.Token]{attr: tok}, ttl)
	return tok, nil
}

func getHostAndImage(repo string, allowPrefix bool, source string) (host string, image string, err error) {
	hostAndImage := strings.SplitN(repo, "/", 2)
	if len(hostAndImage) > 1 && format.IsDomainName(hostAndImage[0]) && strings.Contains(hostAndImage[0], ".") {
		if allowPrefix {
			return hostAndImage[0], hostAndImage[1], nil
		}
	} else if source != "" {
		return source, repo, nil
	}

	return "", "", fmt.Errorf("invalid repository: %q, source: %q", repo, source)
}

func (m *Manager) GetTokenWithUser(ctx context.Context, userinfo *url.Userinfo, t *token.Token) (token.Attribute, error) {
	registry, err := m.getRegistry(ctx, t)
	if err != nil {
		return token.Attribute{}, err
	}

	tok, err := m.getToken(ctx, userinfo, t, registry)
	if err != nil {
		return token.Attribute{}, err
	}

	attr := token.Attribute{
		UserID:     tok.UserID,
		TokenID:    tok.TokenID,
		RegistryID: registry.Registry.RegistryID,

		NoRateLimit:        tok.Data.NoRateLimit,
		RateLimitPerSecond: tok.Data.RateLimitPerSecond,
		Weight:             tok.Data.Weight,
		CacheFirst:         tok.Data.CacheFirst,

		NoAllowlist:   tok.Data.NoAllowlist,
		NoBlock:       tok.Data.NoBlock,
		AllowTagsList: tok.Data.AllowTagsList,

		BlobsAgentURL: tok.Data.BlobsAgentURL,
		NoBlobsAgent:  tok.Data.NoBlobsAgent,

		Block:        tok.Data.Block,
		BlockMessage: tok.Data.BlockMessage,
	}

	if !attr.Block {
		if t.Image != "" {
			host, image, err := getHostAndImage(t.Image, registry.Registry.Data.AllowPrefix, registry.Registry.Data.Source)
			if err != nil {
				attr.Block = true
				attr.BlockMessage = err.Error()
			} else {
				attr.Host = host
				attr.Image = image
			}
		}

		if !attr.Block &&
			!attr.NoAllowlist &&
			registry.ImagesMatcher != nil &&
			attr.Host != "" && attr.Image != "" {
			if !registry.ImagesMatcher.Match(attr.Host + "/" + attr.Image) {
				attr.Block = true
				if registry.Registry.Data.AllowlisBlockMessage != "" {
					attr.BlockMessage = registry.Registry.Data.AllowlisBlockMessage
				} else {
					attr.BlockMessage = fmt.Sprintf("image %s/%s on is not allowed", attr.Host, attr.Image)
				}
			}
		}
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
