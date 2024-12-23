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

type UserResponse struct {
	UserID int64 `json:"user_id"`
}

type UpdateNicknameRequest struct {
	Nickname string `json:"nickname"`
}

type UpdatePasswordRequest struct {
	Account     string `json:"account"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type UserController struct {
	key         *rsa.PrivateKey
	adminToken  string
	userService *service.UserService
}

func NewUserController(key *rsa.PrivateKey, adminToken string, userService *service.UserService) *UserController {
	return &UserController{key: key, adminToken: adminToken, userService: userService}
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
		Writes(UserDetailResponse{}).
		Returns(http.StatusOK, "User found. Returns the user's ID and nickname.", UserDetailResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized access. Please provide a valid token.", Error{}).
		Returns(http.StatusNotFound, "User with the specified ID does not exist. Please check the ID and try again.", Error{}))

	ws.Route(ws.PUT("/users/nickname").To(uc.UpdateNickname).
		Doc("Update the nickname.").
		Operation("updateNickname").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Reads(UpdateNicknameRequest{}).
		Writes(UserDetailResponse{}).
		Returns(http.StatusOK, "Nickname updated successfully. Returns the updated user's ID and new nickname.", UserDetailResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized access. Please provide a valid token.", Error{}).
		Returns(http.StatusNotFound, "User with the specified ID does not exist. Please check the ID and try again.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format. Ensure that the new nickname is provided and is valid.", Error{}))

	ws.Route(ws.PUT("/users/password").To(uc.UpdatePassword).
		Doc("Update the user's password.").
		Operation("updatePassword").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Reads(UpdatePasswordRequest{}).
		Writes(UserResponse{}).
		Returns(http.StatusOK, "Password updated successfully.", UserDetailResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized access. Please provide a valid token.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format. Ensure that the old and new passwords are provided.", Error{}))
}

func (uc *UserController) Create(req *restful.Request, resp *restful.Response) {
	if uc.adminToken == "" || uc.adminToken != req.HeaderParameter("Authorization") {
		unauthorizedResponse(resp)
		return
	}

	var userRequest UserRequest
	err := req.ReadEntity(&userRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "UserRequestError", Message: "Failed to read user request: " + err.Error()})
		return
	}

	pwd := defaultPasswordEncoder.Encrypt(userRequest.Password)

	userID, err := uc.userService.Create(req.Request.Context(), userRequest.Nickname, userRequest.Account, pwd)
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

	if !defaultPasswordEncoder.Verify(userRequest.Password, login.Password) {
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

func (uc *UserController) UpdatePassword(req *restful.Request, resp *restful.Response) {
	session, err := getSession(uc.key, req)
	if err != nil {
		unauthorizedResponse(resp)
		return
	}

	var updateRequest UpdatePasswordRequest
	if err := req.ReadEntity(&updateRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "PasswordUpdateError", Message: "Failed to read password update request: " + err.Error()})
		return
	}

	login, err := uc.userService.GetLoginByAccount(req.Request.Context(), updateRequest.Account)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusForbidden, Error{Code: "LoginNotFoundError", Message: "Login not found for the specified user: " + err.Error()})
		return
	}

	if login.UserID != session.UserID {
		resp.WriteHeaderAndEntity(http.StatusForbidden, Error{Code: "LoginNotFoundError", Message: "Login not found for the specified user: " + err.Error()})
		return
	}

	if !defaultPasswordEncoder.Verify(updateRequest.OldPassword, login.Password) {
		resp.WriteHeaderAndEntity(http.StatusForbidden, Error{Code: "InvalidCredentialsError", Message: "Invalid old password"})
		return
	}

	newPwd := defaultPasswordEncoder.Encrypt(updateRequest.NewPassword)
	if err := uc.userService.UpdatePassword(req.Request.Context(), updateRequest.Account, newPwd); err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "PasswordUpdateError", Message: "Failed to update password: " + err.Error()})
		return
	}

	resp.WriteHeaderAndEntity(http.StatusOK, UserResponse{UserID: session.UserID})
}
