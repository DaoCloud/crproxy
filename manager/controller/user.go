package controller

import (
	"crypto/rsa"
	"net/http"

	"github.com/daocloud/crproxy/manager/service"
	"github.com/emicklei/go-restful/v3"
)

type UserRequest struct {
	Nickname string `json:"nickname,omitempty"`
	Account  string `json:"account"`
	Password string `json:"password"`
}

type UserDetailResponse struct {
	UserID   int64  `json:"user_id"`
	Nickname string `json:"nickname"`
}

type UserLoginRequest struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

type UserLoginResponse struct {
	Token string `json:"token"`
}

type UpdateNicknameRequest struct {
	Nickname string `json:"nickname"`
}

type UserController struct {
	key         *rsa.PrivateKey
	userService *service.UserService
}

func NewUserController(key *rsa.PrivateKey, userService *service.UserService) *UserController {
	return &UserController{key: key, userService: userService}
}

func (uc *UserController) RegisterRoutes(ws *restful.WebService) {
	ws.Route(ws.POST("/users").To(uc.Create).
		Doc("Create a new user with account and password.").
		Operation("createUser").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Reads(UserRequest{}).
		Writes(UserDetailResponse{}).
		Returns(http.StatusCreated, "User created successfully. Returns the created user's ID and nickname.", UserDetailResponse{}).
		Returns(http.StatusBadRequest, "Invalid request format. Ensure that the nickname, account, and password are provided and are valid.", Error{}))

	ws.Route(ws.POST("/users/login").To(uc.GetUserLogin).
		Doc("Retrieve a token by login account.").
		Operation("userLogin").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Reads(UserLoginRequest{}).
		Writes(UserLoginResponse{}).
		Returns(http.StatusOK, "Token retrieved successfully.", UserLoginResponse{}).
		Returns(http.StatusUnauthorized, "Invalid account or password.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format. Ensure that the account and password are provided.", Error{}))

	ws.Route(ws.GET("/users").To(uc.Get).
		Doc("Retrieve a user.").
		Operation("getUser").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Param(ws.HeaderParameter("Authorization", "Bearer <token>")).
		Writes(UserDetailResponse{}).
		Returns(http.StatusOK, "User found. Returns the user's ID and nickname.", UserDetailResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized access. Please provide a valid token.", Error{}).
		Returns(http.StatusNotFound, "User with the specified ID does not exist. Please check the ID and try again.", Error{}))

	ws.Route(ws.PUT("/users/nickname").To(uc.UpdateNickname).
		Doc("Update the nickname of an existing user identified by their unique ID.").
		Operation("updateNickname").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Param(ws.HeaderParameter("Authorization", "Bearer <token>")).
		Reads(UpdateNicknameRequest{}).
		Writes(UserDetailResponse{}).
		Returns(http.StatusOK, "Nickname updated successfully. Returns the updated user's ID and new nickname.", UserDetailResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized access. Please provide a valid token.", Error{}).
		Returns(http.StatusNotFound, "User with the specified ID does not exist. Please check the ID and try again.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format. Ensure that the new nickname is provided and is valid.", Error{}))
}

func (uc *UserController) Create(req *restful.Request, resp *restful.Response) {
	var userRequest UserRequest
	err := req.ReadEntity(&userRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "UserRequestError", Message: "Failed to read user request: " + err.Error()})
		return
	}

	userID, err := uc.userService.Create(req.Request.Context(), userRequest.Nickname, userRequest.Account, userRequest.Password)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "UserCreationError", Message: "Failed to create user: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusCreated, UserDetailResponse{UserID: userID, Nickname: userRequest.Nickname})
}

func (uc *UserController) GetUserLogin(req *restful.Request, resp *restful.Response) {
	var userRequest UserRequest
	err := req.ReadEntity(&userRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "UserRequestError", Message: "Failed to read login request: " + err.Error()})
		return
	}

	login, err := uc.userService.GetLoginByAccount(req.Request.Context(), userRequest.Account)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusForbidden, Error{Code: "LoginNotFoundError", Message: "Login not found for the specified account: " + err.Error()})
		return
	}

	if login.Password != userRequest.Password {
		resp.WriteHeaderAndEntity(http.StatusForbidden, Error{Code: "InvalidCredentialsError", Message: "Invalid account or password"})
		return
	}

	token, err := generateJWT(uc.key, Session{
		UserID: login.UserID,
	})
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "TokenGenerationError", Message: "Failed to generate token: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusOK, UserLoginResponse{
		Token: token,
	})
}

func (uc *UserController) Get(req *restful.Request, resp *restful.Response) {
	session, err := getSession(uc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	user, err := uc.userService.GetByID(req.Request.Context(), session.UserID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "UserNotFoundError", Message: "User with the specified ID does not exist: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusOK, UserDetailResponse{UserID: user.UserID, Nickname: user.Nickname})
}

func (uc *UserController) UpdateNickname(req *restful.Request, resp *restful.Response) {
	session, err := getSession(uc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	var updateRequest UpdateNicknameRequest
	if err := req.ReadEntity(&updateRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "NicknameUpdateError", Message: "Failed to read nickname update request: " + err.Error()})
		return
	}

	if err := uc.userService.UpdateNickname(req.Request.Context(), session.UserID, updateRequest.Nickname); err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "NicknameUpdateError", Message: "Failed to update nickname: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusOK, UserDetailResponse{UserID: session.UserID, Nickname: updateRequest.Nickname})
}
