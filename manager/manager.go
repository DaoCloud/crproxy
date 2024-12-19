package manager

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/daocloud/crproxy/manager/controller"
	"github.com/daocloud/crproxy/manager/dao"
	"github.com/daocloud/crproxy/manager/service"
	"github.com/daocloud/crproxy/token"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/wzshiming/swaggerui"
)

type Manager struct {
	key *rsa.PrivateKey
	db  *sql.DB

	UserDAO  *dao.User
	LoginDAO *dao.Login
	TokenDAO *dao.Token

	UserService     *service.UserService
	UserController  *controller.UserController
	TokenService    *service.TokenService
	TokenController *controller.TokenController

	tokenCache map[string]tokenTTL
	cacheMutex sync.RWMutex
	cacheTTL   time.Duration
}

func NewManager(key *rsa.PrivateKey, db *sql.DB, cacheTTL time.Duration) *Manager {
	m := &Manager{
		key:        key,
		db:         db,
		tokenCache: map[string]tokenTTL{},
		cacheTTL:   cacheTTL,
	}
	return m
}

func (m *Manager) InitTable(ctx context.Context) {
	ctx = dao.WithDB(ctx, m.db)
	m.UserDAO.InitTable(ctx)
	m.LoginDAO.InitTable(ctx)
	m.TokenDAO.InitTable(ctx)
}

func (m *Manager) Register(container *restful.Container) {
	m.UserDAO = dao.NewUser()
	m.LoginDAO = dao.NewLogin()
	m.TokenDAO = dao.NewToken()

	m.UserService = service.NewUserService(m.db, m.UserDAO, m.LoginDAO)
	m.UserController = controller.NewUserController(m.key, m.UserService)
	m.TokenService = service.NewTokenService(m.db, m.TokenDAO)
	m.TokenController = controller.NewTokenController(m.key, m.TokenService)

	ws := new(restful.WebService)
	m.UserController.RegisterRoutes(ws)
	m.TokenController.RegisterRoutes(ws)

	container.Add(ws)

	config := restfulspec.Config{
		WebServices: []*restful.WebService{ws},
		APIPath:     "/swagger.json",
	}

	container.Add(restfulspec.NewOpenAPIService(config))

	container.Handle("/swaggerui/", http.FileServerFS(swaggerui.FS))
}

func (m *Manager) GetToken(ctx context.Context, userinfo *url.Userinfo, t *token.Token) (token.Attribute, error) {
	pwd, _ := userinfo.Password()
	username := userinfo.Username()

	m.cacheMutex.RLock()
	cached, found := m.tokenCache[username]
	m.cacheMutex.RUnlock()

	if found && time.Since(cached.last) < m.cacheTTL {
		return cached.attr, cached.err
	}

	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	cached, found = m.tokenCache[username]
	if found && time.Since(cached.last) < m.cacheTTL {
		return cached.attr, cached.err
	}

	tt, err := m.TokenService.GetByAccount(ctx, username, pwd)
	if err != nil {
		if ctx.Err() == nil {
			m.tokenCache[username] = tokenTTL{err: err, last: time.Now()}
		}
		return token.Attribute{}, err
	}

	var attr token.Attribute
	err = json.Unmarshal([]byte(tt.Data), &attr)
	if err != nil {
		m.tokenCache[username] = tokenTTL{err: err, last: time.Now()}
		return token.Attribute{}, err
	}

	attr.UserID = tt.UserID
	attr.TokenID = tt.TokenID

	m.tokenCache[username] = tokenTTL{attr: attr, last: time.Now()}

	return attr, nil
}

type tokenTTL struct {
	err  error
	attr token.Attribute
	last time.Time
}
