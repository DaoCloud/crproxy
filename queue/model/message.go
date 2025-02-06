package model

import (
	"database/sql/driver"
	"time"
)

type MessageStatus uint64

const (
	StatusPending    MessageStatus = 0
	StatusProcessing MessageStatus = 10
	StatusCompleted  MessageStatus = 20
	StatusFailed     MessageStatus = 30
)

type Message struct {
	MessageID     int64
	Content       string
	Lease         string
	Priority      int
	Status        MessageStatus
	Data          MessageAttr
	LastHeartbeat time.Time
}

type MessageAttr struct {
	Error string `json:"error,omitempty"`

	Host     string `json:"host,omitempty"`
	Image    string `json:"image,omitempty"`
	Progress int64  `json:"progress,omitempty"`
	Size     int64  `json:"size,omitempty"`

	Spec []byte `json:"spec,omitempty"`

	// Deprecate
	Blobs []Blob `json:"blobs,omitempty"`
}

type Blob struct {
	Digest   string `json:"digest"`
	Progress int64  `json:"progress"`
	Size     int64  `json:"size"`
	Error    string `json:"error,omitempty"`
}

func (n *MessageAttr) Scan(value any) error {
	if value == nil {
		return nil
	}
	*n = unmarshal[MessageAttr](asString(value))
	return nil
}

func (n MessageAttr) Value() (driver.Value, error) {
	return marshal(n), nil
}
