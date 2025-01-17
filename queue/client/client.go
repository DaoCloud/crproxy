package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/daocloud/crproxy/queue/model"
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

type MessageClient struct {
	httpClient *http.Client
	baseURL    string
	adminToken string
}

func NewMessageClient(httpClient *http.Client, baseURL string, adminToken string) *MessageClient {
	return &MessageClient{
		httpClient: httpClient,
		baseURL:    baseURL,
		adminToken: adminToken,
	}
}

func (c *MessageClient) Create(ctx context.Context, content string, priority int) (MessageResponse, error) {
	messageRequest := MessageRequest{Content: content, Priority: priority}
	body, err := json.Marshal(messageRequest)
	if err != nil {
		return MessageResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/messages", bytes.NewBuffer(body))
	if err != nil {
		return MessageResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return MessageResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return MessageResponse{}, handleErrorResponse(resp)
	}

	var messageResponse MessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&messageResponse); err != nil {
		return MessageResponse{}, err
	}

	return messageResponse, nil
}

func (c *MessageClient) List(ctx context.Context) ([]MessageResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/messages", nil)
	if err != nil {
		return nil, err
	}
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var messages []MessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return nil, err
	}

	return messages, nil
}

func (c *MessageClient) WatchList(ctx context.Context) (chan MessageResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/messages?watch=1", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("watch", "1")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, handleErrorResponse(resp)
	}

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		defer resp.Body.Close()
		return nil, handleErrorResponse(resp)
	}

	messageChannel := make(chan MessageResponse)

	go func() {
		defer resp.Body.Close()
		defer close(messageChannel)
		decoder := json.NewDecoder(resp.Body)
		for {
			var message MessageResponse
			err := decoder.Decode(&message)
			if err != nil {
				return
			}

			messageChannel <- message
		}
	}()

	return messageChannel, nil
}

func (c *MessageClient) Get(ctx context.Context, messageID int64) (MessageResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/messages/"+strconv.FormatInt(messageID, 10), nil)
	if err != nil {
		return MessageResponse{}, err
	}
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return MessageResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MessageResponse{}, handleErrorResponse(resp)
	}

	var messageResponse MessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&messageResponse); err != nil {
		return MessageResponse{}, err
	}

	return messageResponse, nil
}

func (c *MessageClient) Watch(ctx context.Context, messageID int64) (chan MessageResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/messages/"+strconv.FormatInt(messageID, 10)+"?watch=1", nil)
	if err != nil {
		return nil, err
	}
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, handleErrorResponse(resp)
	}

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		defer resp.Body.Close()
		return nil, handleErrorResponse(resp)
	}

	messageChannel := make(chan MessageResponse)

	go func() {
		defer resp.Body.Close()
		defer close(messageChannel)
		decoder := json.NewDecoder(resp.Body)
		for {
			var message MessageResponse
			err := decoder.Decode(&message)
			if err != nil {
				return
			}
			messageChannel <- message
		}
	}()

	return messageChannel, nil
}

func (c *MessageClient) Consume(ctx context.Context, messageID int64, lease string) (MessageResponse, error) {
	completedRequest := CompletedRequest{Lease: lease}
	body, err := json.Marshal(completedRequest)
	if err != nil {
		return MessageResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/messages/"+strconv.FormatInt(messageID, 10)+"/consume", bytes.NewBuffer(body))
	if err != nil {
		return MessageResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return MessageResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MessageResponse{}, handleErrorResponse(resp)
	}

	var messageResponse MessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&messageResponse); err != nil {
		return MessageResponse{}, err
	}

	return messageResponse, nil
}

func (c *MessageClient) Heartbeat(ctx context.Context, messageID int64, heartbeatRequest HeartbeatRequest) error {
	body, err := json.Marshal(heartbeatRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/messages/"+strconv.FormatInt(messageID, 10)+"/heartbeat", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
	}

	return nil
}

func (c *MessageClient) Complete(ctx context.Context, messageID int64, completedRequest CompletedRequest) error {
	body, err := json.Marshal(completedRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/messages/"+strconv.FormatInt(messageID, 10)+"/complete", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
	}

	return nil
}

func (c *MessageClient) Failed(ctx context.Context, messageID int64, failedRequest FailedRequest) error {
	body, err := json.Marshal(failedRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/messages/"+strconv.FormatInt(messageID, 10)+"/failed", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
	}

	return nil
}

func (c *MessageClient) Cancel(ctx context.Context, messageID int64, cancelRequest CancelRequest) error {
	body, err := json.Marshal(cancelRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/messages/"+strconv.FormatInt(messageID, 10)+"/cancel", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return handleErrorResponse(resp)
	}

	return nil
}

func handleErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var errResponse Error

	err = json.Unmarshal(body, &errResponse)
	if err != nil {
		return fmt.Errorf("Error %s", body)
	}
	return fmt.Errorf("error: %s, message: %s", errResponse.Code, errResponse.Message)
}
