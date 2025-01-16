package queue

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"

	"github.com/daocloud/crproxy/queue/controller"
	"github.com/daocloud/crproxy/queue/dao"
	"github.com/daocloud/crproxy/queue/service"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-openapi/spec"
)

type QueueManager struct {
	adminToken string
	db         *sql.DB

	MessageDAO *dao.Message

	MessageService *service.MessageService

	MessageController *controller.MessageController
}

func NewQueueManager(adminToken string, db *sql.DB) *QueueManager {
	m := &QueueManager{
		adminToken: adminToken,
		db:         db,
	}
	return m
}

func (m *QueueManager) InitTable(ctx context.Context) {
	ctx = dao.WithDB(ctx, m.db)
	m.MessageDAO.InitTable(ctx)
}

func (m *QueueManager) Register(container *restful.Container) {
	m.MessageDAO = dao.NewMessage()

	m.MessageService = service.NewMessageService(m.db, m.MessageDAO)
	m.MessageController = controller.NewMessageController(m.MessageService)

	ws := new(restful.WebService)
	ws.Path("/apis/v1/")

	if m.adminToken != "" {
		ws.Filter(func(req *restful.Request, resp *restful.Response, fc *restful.FilterChain) {
			auth := req.HeaderParameter("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				resp.WriteErrorString(http.StatusForbidden, "Forbidden")
				return
			}

			if auth[7:] != m.adminToken {
				resp.WriteErrorString(http.StatusForbidden, "Forbidden")
				return
			}

			fc.ProcessFilter(req, resp)
		})
	}
	m.MessageController.RegisterRoutes(ws)

	container.Add(ws)

	config := restfulspec.Config{
		WebServices: []*restful.WebService{ws},
		APIPath:     "/swagger.json",
		PostBuildSwaggerObjectHandler: func(s *spec.Swagger) {
			s.Info = &spec.Info{}
			s.Info.Title = "CRProxy Queue Manager"
			s.Schemes = []string{"https", "http"}
			s.SecurityDefinitions = spec.SecurityDefinitions{
				"BearerHeader": {
					SecuritySchemeProps: spec.SecuritySchemeProps{
						Description: `Enter the token with the "Bearer token"`,
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

func (m *QueueManager) Schedule(ctx context.Context, logger *slog.Logger) {
	go m.MessageController.Schedule(ctx, logger)
}
