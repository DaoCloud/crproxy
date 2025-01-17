package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/daocloud/crproxy/queue/model"
	"github.com/daocloud/crproxy/queue/service"
	"github.com/emicklei/go-restful/v3"
)

type MessageRequest struct {
	Content  string `json:"content"`
	Priority int    `json:"priority"`
}

type MessageResponse struct {
	MessageID     int64               `json:"id"`
	Content       string              `json:"content"`
	Priority      int                 `json:"priority"`
	Status        model.MessageStatus `json:"status"`
	Data          model.MessageAttr   `json:"data,omitempty"`
	LastHeartbeat time.Time           `json:"last_heartbeat"`
}

type ConsumeRequest struct {
	Lease string `json:"lease"`
}

type HeartbeatRequest struct {
	Data  model.MessageAttr `json:"data"`
	Lease string            `json:"lease"`
}

type CompletedRequest struct {
	Lease string `json:"lease"`
}

type FailedRequest struct {
	Lease string            `json:"lease"`
	Data  model.MessageAttr `json:"data"`
}

type CancelRequest struct {
	Lease string `json:"lease"`
}

type MessageController struct {
	messageService *service.MessageService

	watchChannelsMut sync.Mutex
	watchChannels    map[int64][]chan MessageResponse

	watchListChannelsMut sync.Mutex
	watchListChannels    []chan MessageResponse
}

func (mc *MessageController) newWatchChannel(messageID int64) chan MessageResponse {
	ch := make(chan MessageResponse, 1)
	mc.watchChannelsMut.Lock()
	defer mc.watchChannelsMut.Unlock()
	mc.watchChannels[messageID] = append(mc.watchChannels[messageID], ch)
	return ch
}

func (mc *MessageController) cancelWatchChannel(messageID int64, ch chan MessageResponse) {
	mc.watchChannelsMut.Lock()
	defer mc.watchChannelsMut.Unlock()
	channels := mc.watchChannels[messageID]
	for i, channel := range channels {
		if channel == ch {
			mc.watchChannels[messageID] = append(channels[:i], channels[i+1:]...)
			break
		}
	}

	if len(mc.watchChannels[messageID]) == 0 {
		delete(mc.watchChannels, messageID)
	}
}

func (mc *MessageController) updateWatchChannel(messageID int64, mr MessageResponse) {
	mc.watchChannelsMut.Lock()
	defer mc.watchChannelsMut.Unlock()
	for _, ch := range mc.watchChannels[messageID] {
		select {
		case ch <- mr:
		default:
		}
	}
}

func (mc *MessageController) newWatchListChannel() chan MessageResponse {
	ch := make(chan MessageResponse, 1)
	mc.watchListChannelsMut.Lock()
	defer mc.watchListChannelsMut.Unlock()
	mc.watchListChannels = append(mc.watchListChannels, ch)
	return ch
}

func (mc *MessageController) cancelWatchListChannel(ch chan MessageResponse) {
	mc.watchListChannelsMut.Lock()
	defer mc.watchListChannelsMut.Unlock()
	for i, channel := range mc.watchListChannels {
		if channel == ch {
			mc.watchListChannels = append(mc.watchListChannels[:i], mc.watchListChannels[i+1:]...)
			break
		}
	}
}

func (mc *MessageController) updateWatchListChannels(mr MessageResponse) {
	mc.watchListChannelsMut.Lock()
	defer mc.watchListChannelsMut.Unlock()
	for _, ch := range mc.watchListChannels {
		select {
		case ch <- mr:
		default:
		}
	}
}

func NewMessageController(messageService *service.MessageService) *MessageController {
	return &MessageController{messageService: messageService, watchChannels: map[int64][]chan MessageResponse{}}
}

func (mc *MessageController) RegisterRoutes(ws *restful.WebService) {
	ws.Route(ws.PUT("/messages").To(mc.Create).
		Doc("Try create a new message.").
		Operation("createMessage").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Reads(MessageRequest{}).
		Writes(MessageResponse{}).
		Returns(http.StatusCreated, "Message created successfully.", MessageResponse{}).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.GET("/messages").To(mc.List).
		Doc("List all messages.").
		Operation("listMessages").
		Param(ws.QueryParameter("watch", "Watch the message for updates").DataType("boolean")).
		Produces(restful.MIME_JSON).
		Writes([]MessageResponse{}).
		Returns(http.StatusOK, "Messages retrieved successfully.", []MessageResponse{}).
		Returns(http.StatusInternalServerError, "Failed to retrieve messages.", Error{}).
		Returns(http.StatusNoContent, "No messages available.", Error{}))

	ws.Route(ws.GET("/messages/{message_id}").To(mc.Get).
		Doc("Retrieve a message by ID.").
		Operation("getMessage").
		Param(ws.PathParameter("message_id", "message ID").DataType("integer")).
		Param(ws.QueryParameter("watch", "Watch the message for updates").DataType("boolean")).
		Produces(restful.MIME_JSON).
		Writes(MessageResponse{}).
		Returns(http.StatusOK, "Message found.", MessageResponse{}).
		Returns(http.StatusNotFound, "Message not found.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.POST("/messages/{message_id}/consume").To(mc.Consume).
		Doc("Consume a message by ID.").
		Operation("consume").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Param(ws.PathParameter("message_id", "message ID").DataType("integer")).
		Reads(CompletedRequest{}).
		Writes(MessageResponse{}).
		Returns(http.StatusOK, "Message consumed successfully.", MessageResponse{}).
		Returns(http.StatusNotFound, "Message not found.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.PATCH("/messages/{message_id}/heartbeat").To(mc.Heartbeat).
		Doc("Set heartbeat for a message by ID.").
		Operation("heartbeat").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Param(ws.PathParameter("message_id", "message ID").DataType("integer")).
		Reads(HeartbeatRequest{}).
		Writes(Error{}).
		Returns(http.StatusNoContent, "Heartbeat updated successfully.", nil).
		Returns(http.StatusNotFound, "Message not found.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.PATCH("/messages/{message_id}/complete").To(mc.Completed).
		Doc("Set a message as completed by ID.").
		Operation("setCompleted").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Param(ws.PathParameter("message_id", "message ID").DataType("integer")).
		Reads(CompletedRequest{}).
		Writes(Error{}).
		Returns(http.StatusNoContent, "Message failed successfully.", nil).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))

	ws.Route(ws.PATCH("/messages/{message_id}/failed").To(mc.Failed).
		Doc("Set a message as failed by ID.").
		Operation("setFailed").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Param(ws.PathParameter("message_id", "message ID").DataType("integer")).
		Reads(FailedRequest{}).
		Writes(Error{}).
		Returns(http.StatusNoContent, "Message failed successfully.", nil).
		Returns(http.StatusNotFound, "Message not found.", Error{}))

	ws.Route(ws.PATCH("/messages/{message_id}/cancel").To(mc.Cancel).
		Doc("Cancel a message by ID.").
		Operation("cancel").
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON).
		Param(ws.PathParameter("message_id", "message ID").DataType("integer")).
		Reads(CancelRequest{}).
		Writes(Error{}).
		Returns(http.StatusNoContent, "Message canceled successfully.", nil).
		Returns(http.StatusNotFound, "Message not found.", Error{}).
		Returns(http.StatusBadRequest, "Invalid request format.", Error{}))
}

func (mc *MessageController) Schedule(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			staleList, err := mc.messageService.GetStale(ctx)
			if err != nil {
				logger.Error("ReleaseStale", "error", err)
			} else {
				for _, item := range staleList {
					err := mc.messageService.ResetToPending(ctx, item.MessageID)
					if err != nil {
						logger.Error("ResetToPending", "error", err)
					} else {
						data := MessageResponse{MessageID: item.MessageID, Content: item.Content, Priority: item.Priority, Status: item.Status, Data: item.Data, LastHeartbeat: item.LastHeartbeat}
						mc.updateWatchListChannels(data)
						mc.updateWatchChannel(item.MessageID, data)
					}
				}
			}

			cleanList, err := mc.messageService.GetCompletedAndFailed(ctx)
			if err != nil {
				logger.Error("DeleteCompletedAndFailed", "error", err)
			} else {
				for _, item := range cleanList {
					err := mc.messageService.DeleteByID(ctx, item.MessageID)
					if err != nil {
						logger.Error("DeleteByID", "error", err)
					}
				}
			}

			err = mc.messageService.CleanUp(ctx)
			if err != nil {
				logger.Error("CleanUp", "error", err)
			}
		}
	}
}

func (mc *MessageController) Create(req *restful.Request, resp *restful.Response) {
	var messageRequest MessageRequest
	if err := req.ReadEntity(&messageRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "MessageRequestError", Message: "Failed to read message request: " + err.Error()})
		return
	}

	message, err := mc.messageService.GetByContent(req.Request.Context(), messageRequest.Content)
	if err == nil {
		data := MessageResponse{
			MessageID:     message.MessageID,
			Content:       message.Content,
			Priority:      message.Priority,
			Status:        message.Status,
			Data:          message.Data,
			LastHeartbeat: message.LastHeartbeat,
		}

		if message.Status == model.StatusPending && messageRequest.Priority > message.Priority {
			if err := mc.messageService.UpdatePriorityByID(req.Request.Context(), message.MessageID, messageRequest.Priority); err != nil {
				resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "MessageUpdateError", Message: "Failed to update message priority: " + err.Error()})
				return
			}
			data.Priority = messageRequest.Priority
			mc.updateWatchListChannels(data)
		}
		resp.WriteHeaderAndEntity(http.StatusOK, data)
		return
	}

	if !errors.Is(err, sql.ErrNoRows) {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "MessageRetrievalError", Message: "Failed to retrieve message: " + err.Error()})
		return
	}

	newMessage := model.Message{
		Content:  messageRequest.Content,
		Priority: messageRequest.Priority,
	}
	messageID, err := mc.messageService.Create(req.Request.Context(), newMessage)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "MessageCreationError", Message: "Failed to create message: " + err.Error()})
		return
	}

	data := MessageResponse{
		MessageID: messageID,
		Content:   messageRequest.Content,
		Priority:  messageRequest.Priority,
	}

	mc.updateWatchListChannels(data)
	resp.WriteHeaderAndEntity(http.StatusCreated, data)
}

func (mc *MessageController) List(req *restful.Request, resp *restful.Response) {
	messages, err := mc.messageService.List(req.Request.Context())
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, Error{Code: "MessageListError", Message: "Failed to retrieve messages: " + err.Error()})
		return
	}
	var messageResponses = make([]MessageResponse, 0, len(messages))
	for _, message := range messages {
		messageResponses = append(messageResponses, MessageResponse{
			MessageID:     message.MessageID,
			Content:       message.Content,
			Priority:      message.Priority,
			Status:        message.Status,
			Data:          message.Data,
			LastHeartbeat: message.LastHeartbeat,
		})
	}

	watch, _ := strconv.ParseBool(req.QueryParameter("watch"))
	if !watch {
		resp.WriteHeaderAndEntity(http.StatusOK, messageResponses)
		return
	}

	resp.Header().Set("Transfer-Encoding", "chunked")
	resp.Header().Set("X-Accel-Buffering", "no")
	resp.Header().Set("Content-Type", "text/event-stream")
	resp.Header().Set("Cache-Control", "no-cache")
	resp.Header().Set("Connection", "keep-alive")
	resp.WriteHeader(http.StatusOK)

	watchCh := mc.newWatchListChannel()
	defer mc.cancelWatchListChannel(watchCh)

	encoder := json.NewEncoder(resp.ResponseWriter)

	for _, d := range messageResponses {
		encoder.Encode(d)
	}
	resp.Flush()

	messageResponses = nil

	ctx := req.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-watchCh:
			if !ok {
				return
			}

			encoder.Encode(data)
			resp.Flush()
		}
	}
}

func (mc *MessageController) Get(req *restful.Request, resp *restful.Response) {
	messageIDStr := req.PathParameter("message_id")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidIDError", Message: "Invalid message ID: " + err.Error()})
		return
	}

	message, err := mc.messageService.GetByID(req.Request.Context(), messageID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "MessageNotFoundError", Message: "Message not found: " + err.Error()})
		return
	}

	if message.Status != model.StatusProcessing && message.Status != model.StatusPending {
		resp.WriteHeaderAndEntity(http.StatusOK, MessageResponse{MessageID: message.MessageID, Content: message.Content, Priority: message.Priority, Status: message.Status, Data: message.Data, LastHeartbeat: message.LastHeartbeat})
		return
	}

	watch, _ := strconv.ParseBool(req.QueryParameter("watch"))
	if !watch {
		resp.WriteHeaderAndEntity(http.StatusOK, MessageResponse{MessageID: message.MessageID, Content: message.Content, Priority: message.Priority, Status: message.Status, Data: message.Data, LastHeartbeat: message.LastHeartbeat})
		return
	}

	resp.Header().Set("Transfer-Encoding", "chunked")
	resp.Header().Set("X-Accel-Buffering", "no")
	resp.Header().Set("Content-Type", "text/event-stream")
	resp.Header().Set("Cache-Control", "no-cache")
	resp.Header().Set("Connection", "keep-alive")
	resp.WriteHeader(http.StatusOK)

	watchCh := mc.newWatchChannel(messageID)
	defer mc.cancelWatchChannel(messageID, watchCh)

	mc.updateWatchChannel(messageID, MessageResponse{MessageID: message.MessageID, Content: message.Content, Priority: message.Priority, Status: message.Status, Data: message.Data, LastHeartbeat: message.LastHeartbeat})

	encoder := json.NewEncoder(resp.ResponseWriter)

	ctx := req.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-watchCh:
			if !ok {
				return
			}

			encoder.Encode(data)
			resp.Flush()

			if data.Status != model.StatusProcessing && data.Status != model.StatusPending {
				return
			}
		}
	}
}

func (mc *MessageController) Consume(req *restful.Request, resp *restful.Response) {
	messageIDStr := req.PathParameter("message_id")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidIDError", Message: "Invalid message ID: " + err.Error()})
		return
	}

	var completedRequest CompletedRequest
	if err := req.ReadEntity(&completedRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "CompletedRequestError", Message: "Failed to read completed request: " + err.Error()})
		return
	}

	message, err := mc.messageService.Consume(req.Request.Context(), messageID, completedRequest.Lease)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotAcceptable, Error{Code: "MessageNotAcceptableError", Message: "Message not found: " + err.Error()})
		return
	}

	data := MessageResponse{MessageID: message.MessageID, Content: message.Content, Priority: message.Priority, Status: message.Status, Data: message.Data, LastHeartbeat: message.LastHeartbeat}
	mc.updateWatchChannel(messageID, data)
	mc.updateWatchListChannels(data)

	resp.WriteHeaderAndEntity(http.StatusOK, data)
}

func (mc *MessageController) Heartbeat(req *restful.Request, resp *restful.Response) {
	messageIDStr := req.PathParameter("message_id")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidIDError", Message: "Invalid message ID: " + err.Error()})
		return
	}

	var heartbeatRequest HeartbeatRequest
	if err := req.ReadEntity(&heartbeatRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "HeartbeatRequestError", Message: "Failed to read heartbeat request: " + err.Error()})
		return
	}

	if err := mc.messageService.Heartbeat(req.Request.Context(), messageID, heartbeatRequest.Data, heartbeatRequest.Lease); err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotAcceptable, Error{Code: "MessageNotAcceptableError", Message: "Message not found: " + err.Error()})
		return
	}

	curr, err := mc.messageService.GetByID(context.Background(), messageID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "MessageNotFoundError", Message: "Message not found after heartbeat: " + err.Error()})
		return
	}

	data := MessageResponse{MessageID: curr.MessageID, Content: curr.Content, Priority: curr.Priority, Status: curr.Status, Data: curr.Data, LastHeartbeat: curr.LastHeartbeat}

	mc.updateWatchChannel(messageID, data)
	mc.updateWatchListChannels(data)

	resp.WriteHeader(http.StatusNoContent)
}

func (mc *MessageController) Completed(req *restful.Request, resp *restful.Response) {
	messageIDStr := req.PathParameter("message_id")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidIDError", Message: "Invalid message ID: " + err.Error()})
		return
	}

	var completedRequest CompletedRequest
	if err := req.ReadEntity(&completedRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "CompletedRequestError", Message: "Failed to read completed request: " + err.Error()})
		return
	}

	if err := mc.messageService.Completed(req.Request.Context(), messageID, completedRequest.Lease); err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotAcceptable, Error{Code: "MessageNotAcceptabledError", Message: "Message not found: " + err.Error()})
		return
	}

	curr, err := mc.messageService.GetByID(context.Background(), messageID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "MessageNotFoundError", Message: "Message not found after completion: " + err.Error()})
		return
	}

	data := MessageResponse{MessageID: curr.MessageID, Content: curr.Content, Priority: curr.Priority, Status: curr.Status, Data: curr.Data, LastHeartbeat: curr.LastHeartbeat}

	mc.updateWatchChannel(messageID, data)
	mc.updateWatchListChannels(data)

	resp.WriteHeader(http.StatusNoContent)
}

func (mc *MessageController) Failed(req *restful.Request, resp *restful.Response) {
	messageIDStr := req.PathParameter("message_id")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidIDError", Message: "Invalid message ID: " + err.Error()})
		return
	}

	var failedRequest FailedRequest
	if err := req.ReadEntity(&failedRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "FailedRequestError", Message: "Failed to read failed request: " + err.Error()})
		return
	}

	if err := mc.messageService.Failed(req.Request.Context(), messageID, failedRequest.Lease, failedRequest.Data); err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotAcceptable, Error{Code: "MessageNotAcceptableError", Message: "Message not found: " + err.Error()})
		return
	}

	curr, err := mc.messageService.GetByID(context.Background(), messageID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "MessageNotFoundError", Message: "Message not found after failure: " + err.Error()})
		return
	}

	data := MessageResponse{MessageID: curr.MessageID, Content: curr.Content, Priority: curr.Priority, Status: curr.Status, Data: curr.Data, LastHeartbeat: curr.LastHeartbeat}

	mc.updateWatchChannel(messageID, data)
	mc.updateWatchListChannels(data)

	resp.WriteHeader(http.StatusNoContent)
}

func (mc *MessageController) Cancel(req *restful.Request, resp *restful.Response) {
	messageIDStr := req.PathParameter("message_id")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "InvalidIDError", Message: "Invalid message ID: " + err.Error()})
		return
	}

	var cancelRequest CancelRequest
	if err := req.ReadEntity(&cancelRequest); err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, Error{Code: "FailedRequestError", Message: "Failed to read failed request: " + err.Error()})
		return
	}

	if err := mc.messageService.Cancel(req.Request.Context(), messageID, cancelRequest.Lease); err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotAcceptable, Error{Code: "MessageNotAcceptableError", Message: "Message not found: " + err.Error()})
		return
	}

	curr, err := mc.messageService.GetByID(context.Background(), messageID)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusNotFound, Error{Code: "MessageNotFoundError", Message: "Message not found after failure: " + err.Error()})
		return
	}

	data := MessageResponse{MessageID: curr.MessageID, Content: curr.Content, Priority: curr.Priority, Status: curr.Status, Data: curr.Data, LastHeartbeat: curr.LastHeartbeat}

	mc.updateWatchChannel(messageID, data)
	mc.updateWatchListChannels(data)

	resp.WriteHeader(http.StatusNoContent)
}
