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

type TokenRequest struct {
	Account  string          `json:"account"`
	Password string          `json:"password"`
	Data     model.TokenAttr `json:"data"`
}

type TokenResponse struct {
	TokenID int64 `json:"token_id"`
}

type TokenDetailResponse struct {
	TokenID int64           `json:"token_id"`
	Account string          `json:"account"`
	Data    model.TokenAttr `json:"data"`
}

type TokenController struct {
	key          *rsa.PrivateKey
	tokenService *service.TokenService
}

func NewTokenController(key *rsa.PrivateKey, tokenService *service.TokenService) *TokenController {
	return &TokenController{key: key, tokenService: tokenService}
}

func (tc *TokenController) RegisterRoutes(ws *restful.WebService) {
	ws.Route(ws.POST("/tokens").To(tc.Create).
		Doc("Create a new token for a user.").
		Operation("createToken").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Reads(TokenRequest{}).
		Writes(TokenResponse{}).
		Returns(http.StatusCreated, "Token created successfully.", TokenResponse{}).
		Returns(http.StatusBadRequest, "Invalid request format. Ensure that the token data is provided and is valid.", Error{}))

	ws.Route(ws.GET("/tokens").To(tc.List).
		Doc("Retrieve all tokens by user.").
		Operation("listToken").
		Produces(restful.MIME_JSON).
		Writes([]TokenDetailResponse{}).
		Returns(http.StatusOK, "Tokens found.", []TokenDetailResponse{}).
		Returns(http.StatusNotFound, "No tokens found for the user.", Error{}))

	ws.Route(ws.GET("/tokens/{token_id}").To(tc.Get).
		Doc("Retrieve a token by its ID.").
		Operation("getToken").
		Produces(restful.MIME_JSON).
		Param(ws.PathParameter("token_id", "Token ID").DataType("integer")).
		Writes(TokenDetailResponse{}).
		Returns(http.StatusOK, "Token found.", TokenDetailResponse{}).
		Returns(http.StatusNotFound, "Token not found.", Error{}))

	ws.Route(ws.DELETE("/tokens/{token_id}").To(tc.Delete).
		Doc("Delete a token by its ID.").
		Operation("Token").
		Produces(restful.MIME_JSON).
		Param(ws.PathParameter("token_id", "Token ID").DataType("integer")).
		Returns(http.StatusNoContent, "Token deleted successfully.", nil).
		Returns(http.StatusNotFound, "Token not found.", Error{}))
}

func (tc *TokenController) Create(req *restful.Request, resp *restful.Response) {
	session, err := getSession(tc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	var tokenRequest TokenRequest
	err = req.ReadEntity(&tokenRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "TokenRequestError", Message: "Failed to read token request: " + err.Error()})
		return
	}

	if tokenRequest.Account == "" || tokenRequest.Password == "" {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "MissingCredentialsError", Message: "Account and password must be provided."})
		return
	}

	tokenID, err := tc.tokenService.Create(req.Request.Context(), model.Token{
		UserID:   session.UserID,
		Account:  tokenRequest.Account,
		Password: tokenRequest.Password,
		Data:     tokenRequest.Data,
	})
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "TokenCreationError", Message: "Failed to create token: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusCreated, TokenResponse{TokenID: tokenID})
}

func (tc *TokenController) List(req *restful.Request, resp *restful.Response) {
	session, err := getSession(tc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	tokens, err := tc.tokenService.GetByUserID(req.Request.Context(), session.UserID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "TokensNotFoundError", Message: "No tokens found for the user: " + err.Error()})
		return
	}

	resp.WriteEntity(slices.Map(tokens, func(token model.Token) TokenDetailResponse {
		return TokenDetailResponse{
			TokenID: token.TokenID,
			Account: token.Account,
			Data:    token.Data,
		}
	}))
}

func (tc *TokenController) Get(req *restful.Request, resp *restful.Response) {
	session, err := getSession(tc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	tokenIDStr := req.PathParameter("token_id")
	tokenID, err := strconv.ParseInt(tokenIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidTokenIDError", Message: "Invalid token ID: " + err.Error()})
		return
	}

	token, err := tc.tokenService.Get(req.Request.Context(), tokenID, session.UserID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "TokenNotFoundError", Message: "Token not found: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusOK, TokenDetailResponse{
		TokenID: token.TokenID,
		Account: token.Account,
		Data:    token.Data,
	})
}

func (tc *TokenController) Delete(req *restful.Request, resp *restful.Response) {
	session, err := getSession(tc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	tokenIDStr := req.PathParameter("token_id")
	tokenID, err := strconv.ParseInt(tokenIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidTokenIDError", Message: "Invalid token ID: " + err.Error()})
		return
	}

	if err := tc.tokenService.Delete(req.Request.Context(), tokenID, session.UserID); err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "TokenNotFoundError", Message: "Token not found: " + err.Error()})
		return
	}
	resp.WriteHeader(http.StatusNoContent)
}
