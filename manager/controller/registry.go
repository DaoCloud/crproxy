package controller

import (
	"crypto/rsa"
	"net/http"
	"strconv"

	"github.com/daocloud/crproxy/internal/slices"
	"github.com/daocloud/crproxy/manager/model"
	"github.com/daocloud/crproxy/manager/service"
	"github.com/emicklei/go-restful/v3"
)

type RegistryRequest struct {
	Domain string             `json:"domain"`
	Data   model.RegistryAttr `json:"data"`
}

type RegistryUpdateAllowImagesRequest struct {
	Items        []string `json:"items"`
	BlockMessage string   `json:"block_message"`
}

type RegistryUpdateIPDataRequest struct {
	IPs  []string        `json:"ips"`
	Data model.TokenAttr `json:"data"`
}

type RegistryUpdateAnonymousDataRequest struct {
	Data model.TokenAttr `json:"data"`
}

type RegistryResponse struct {
	RegistryID int64 `json:"registry_id"`
}

type RegistryDetailResponse struct {
	RegistryID int64              `json:"registry_id"`
	UserID     int64              `json:"user_id"`
	Domain     string             `json:"domain"`
	Data       model.RegistryAttr `json:"data"`
}

type RegistryController struct {
	key             *rsa.PrivateKey
	registryService *service.RegistryService
}

func NewRegistryController(key *rsa.PrivateKey, registryService *service.RegistryService) *RegistryController {
	return &RegistryController{key: key, registryService: registryService}
}

func (rc *RegistryController) RegisterRoutes(ws *restful.WebService) {
	ws.Route(ws.POST("/registries").To(rc.Create).
		Doc("Create a new registry for a user.").
		Operation("createRegistry").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Reads(RegistryRequest{}).
		Writes(RegistryResponse{}).
		Returns(http.StatusCreated, "Registry created successfully.", RegistryResponse{}).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.GET("/registries/{registry_id}").To(rc.Get).
		Doc("Retrieve a registry by its ID.").
		Operation("getRegistry").
		Produces(restful.MIME_JSON).
		Param(ws.PathParameter("registry_id", "Registry ID").DataType("integer")).
		Writes(RegistryDetailResponse{}).
		Returns(http.StatusOK, "Registry found.", RegistryDetailResponse{}).
		Returns(http.StatusNotFound, "Registry not found.", Error{}))

	ws.Route(ws.GET("/registries").To(rc.List).
		Doc("Retrieve all registries by user.").
		Operation("listRegistry").
		Produces(restful.MIME_JSON).
		Writes([]RegistryDetailResponse{}).
		Returns(http.StatusOK, "Registries found.", []RegistryDetailResponse{}).
		Returns(http.StatusNotFound, "No registries found for the user.", Error{}))

	ws.Route(ws.PUT("/registries/{registry_id}").To(rc.Update).
		Doc("Update a registry by its ID.").
		Operation("updateRegistry").
		Produces(restful.MIME_JSON).
		Param(ws.PathParameter("registry_id", "Registry ID").DataType("integer")).
		Reads(RegistryRequest{}).
		Returns(http.StatusOK, "Registry updated successfully.", RegistryDetailResponse{}).
		Returns(http.StatusNotFound, "Registry not found.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.PUT("/registries/allow_images").To(rc.UpdateAllowImages).
		Doc("Update allowed images for a registry by its ID.").
		Operation("updateRegistryAllowImages").
		Produces(restful.MIME_JSON).
		Reads(RegistryUpdateAllowImagesRequest{}).
		Returns(http.StatusNoContent, "Registry deleted successfully.", nil).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.PUT("/registries/ips/data").To(rc.UpdateIPData).
		Doc("Update IP attributes for registries.").
		Operation("updateRegistryIPAttr").
		Produces(restful.MIME_JSON).
		Reads(RegistryUpdateIPDataRequest{}).
		Returns(http.StatusNoContent, "IP attributes updated successfully.", nil).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.PUT("/registries/anonymous/data").To(rc.UpdateAnonymousData).
		Doc("Update anonymous attributes for registries.").
		Operation("updateRegistryAnonymousAttr").
		Produces(restful.MIME_JSON).
		Reads(RegistryUpdateAnonymousDataRequest{}).
		Returns(http.StatusNoContent, "Anonymous attributes updated successfully.", nil).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.DELETE("/registries/{registry_id}").To(rc.Delete).
		Doc("Delete a registry by its ID.").
		Operation("deleteRegistry").
		Produces(restful.MIME_JSON).
		Param(ws.PathParameter("registry_id", "Registry ID").DataType("integer")).
		Returns(http.StatusNoContent, "Registry deleted successfully.", nil).
		Returns(http.StatusNotFound, "Registry not found.", Error{}))
}

func (rc *RegistryController) Create(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	var registryRequest RegistryRequest
	err = req.ReadEntity(&registryRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "RegistryRequestError", Message: "Failed to read registry request: " + err.Error()})
		return
	}

	if registryRequest.Domain == "" {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "MissingFieldsError", Message: "Domain and source must be provided."})
		return
	}

	registryID, err := rc.registryService.Create(req.Request.Context(), model.Registry{
		UserID: session.UserID,
		Domain: registryRequest.Domain,
		Data:   registryRequest.Data,
	})
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "RegistryCreationError", Message: "Failed to create registry: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusCreated, RegistryResponse{RegistryID: registryID})
}

func (rc *RegistryController) Get(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	registryIDStr := req.PathParameter("registry_id")
	registryID, err := strconv.ParseInt(registryIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidRegistryIDError", Message: "Invalid registry ID: " + err.Error()})
		return
	}

	registry, err := rc.registryService.GetByID(req.Request.Context(), registryID, session.UserID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "RegistryNotFoundError", Message: "Registry not found: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusOK, RegistryDetailResponse{
		RegistryID: registry.RegistryID,
		UserID:     registry.UserID,
		Domain:     registry.Domain,
		Data:       registry.Data,
	})
}

func (rc *RegistryController) List(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	registries, err := rc.registryService.GetByUserID(req.Request.Context(), session.UserID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "RegistriesNotFoundError", Message: "No registries found for the user: " + err.Error()})
		return
	}

	resp.WriteEntity(slices.Map(registries, func(registry model.Registry) RegistryDetailResponse {
		return RegistryDetailResponse{
			RegistryID: registry.RegistryID,
			UserID:     registry.UserID,
			Domain:     registry.Domain,
			Data:       registry.Data,
		}
	}))
}

func (rc *RegistryController) Update(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	registryIDStr := req.PathParameter("registry_id")
	registryID, err := strconv.ParseInt(registryIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidRegistryIDError", Message: "Invalid registry ID: " + err.Error()})
		return
	}

	var registryRequest RegistryRequest
	err = req.ReadEntity(&registryRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "RegistryRequestError", Message: "Failed to read registry request: " + err.Error()})
		return
	}

	err = rc.registryService.UpdateByID(req.Request.Context(), registryID, session.UserID, model.Registry{Domain: registryRequest.Domain, Data: registryRequest.Data})
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "RegistryUpdateError", Message: "Failed to update registry: " + err.Error()})
		return
	}

	resp.WriteHeader(http.StatusNoContent)
}

func (rc *RegistryController) UpdateAllowImages(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	var registryRequest RegistryUpdateAllowImagesRequest
	err = req.ReadEntity(&registryRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "RegistryRequestError", Message: "Failed to read registry request: " + err.Error()})
		return
	}

	err = rc.registryService.UpdateAllowImages(req.Request.Context(), session.UserID, registryRequest.Items, registryRequest.BlockMessage)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "RegistryUpdateError", Message: "Failed to update registry: " + err.Error()})
		return
	}

	resp.WriteHeader(http.StatusNoContent)
}

func (rc *RegistryController) UpdateIPData(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	var ipAttrRequest RegistryUpdateIPDataRequest
	err = req.ReadEntity(&ipAttrRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "RegistryRequestError", Message: "Failed to read IP attribute request: " + err.Error()})
		return
	}

	err = rc.registryService.UpdateIPData(req.Request.Context(), session.UserID, ipAttrRequest.IPs, ipAttrRequest.Data)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "RegistryUpdateError", Message: "Failed to update IP attributes: " + err.Error()})
		return
	}

	resp.WriteHeader(http.StatusNoContent)
}

func (rc *RegistryController) UpdateAnonymousData(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	var anonymousAttrRequest RegistryUpdateAnonymousDataRequest
	err = req.ReadEntity(&anonymousAttrRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "RegistryRequestError", Message: "Failed to read anonymous attribute request: " + err.Error()})
		return
	}

	err = rc.registryService.UpdateAnonymousData(req.Request.Context(), session.UserID, anonymousAttrRequest.Data)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "RegistryUpdateError", Message: "Failed to update anonymous attributes: " + err.Error()})
		return
	}

	resp.WriteHeader(http.StatusNoContent)
}

func (rc *RegistryController) Delete(req *restful.Request, resp *restful.Response) {
	session, err := getSession(rc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	registryIDStr := req.PathParameter("registry_id")
	registryID, err := strconv.ParseInt(registryIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidRegistryIDError", Message: "Invalid registry ID: " + err.Error()})
		return
	}

	if err := rc.registryService.DeleteByID(req.Request.Context(), registryID, session.UserID); err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "RegistryNotFoundError", Message: "Registry not found: " + err.Error()})
		return
	}
	resp.WriteHeader(http.StatusNoContent)
}
