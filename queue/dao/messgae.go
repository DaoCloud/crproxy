package dao

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/daocloud/crproxy/queue/model"
)

type Message struct{}

func NewMessage() *Message {
	return &Message{}
}

const messageTableSQL = `
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    lease VARCHAR(36) NOT NULL,
    priority INT DEFAULT 0,
    status INT DEFAULT 0,
	data JSON NOT NULL,
	last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    delete_at TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=10000 CHARSET=utf8mb4;
`

func (l *Message) InitTable(ctx context.Context) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, messageTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create messages table: %w", err)
	}
	return nil
}

const createMessageSQL = `
INSERT INTO messages (content, lease, priority, status, data) VALUES (?, ?, ?, ?, ?)
`

func (m *Message) Create(ctx context.Context, message model.Message) (int64, error) {
	db := GetDB(ctx)
	result, err := db.ExecContext(ctx, createMessageSQL, message.Content, message.Lease, message.Priority, model.StatusPending, "{}")
	if err != nil {
		return 0, fmt.Errorf("failed to create message: %w", err)
	}
	return result.LastInsertId()
}

const getMessageByContentSQL = `
SELECT id, content, lease, priority, status, data, last_heartbeat FROM messages WHERE content = ? AND delete_at IS NULL
`

func (m *Message) GetByContent(ctx context.Context, content string) (model.Message, error) {
	db := GetDB(ctx)
	var message model.Message
	err := db.QueryRowContext(ctx, getMessageByContentSQL, content).Scan(&message.MessageID, &message.Content, &message.Lease, &message.Priority, &message.Status, &message.Data, &message.LastHeartbeat)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Message{}, fmt.Errorf("message not found: %w", err)
		}
		return model.Message{}, fmt.Errorf("failed to get message: %w", err)
	}
	return message, nil
}

const getMessageByIDSQL = `
SELECT id, content, lease, priority, status, data, last_heartbeat FROM messages WHERE id = ? AND delete_at IS NULL
`

func (m *Message) GetByID(ctx context.Context, id int64) (model.Message, error) {
	db := GetDB(ctx)
	var message model.Message
	err := db.QueryRowContext(ctx, getMessageByIDSQL, id).Scan(&message.MessageID, &message.Content, &message.Lease, &message.Priority, &message.Status, &message.Data, &message.LastHeartbeat)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Message{}, fmt.Errorf("message not found: %w", err)
		}
		return model.Message{}, fmt.Errorf("failed to get message: %w", err)
	}
	return message, nil
}

const updateMessageByIDSQL = `
UPDATE messages SET content = ?, lease = ?, priority = ?, status = ?, data = ? WHERE id = ? AND delete_at IS NULL
`

func (m *Message) UpdateByID(ctx context.Context, id int64, message model.Message) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, updateMessageByIDSQL, message.Content, message.Lease, message.Priority, message.Status, message.Data, id)
	if err != nil {
		return fmt.Errorf("failed to update message: %w", err)
	}
	return nil
}

const updateMessagePriorityByIDSQL = `
UPDATE messages SET priority = ? WHERE id = ? AND priority < ? AND delete_at IS NULL
`

func (m *Message) UpdatePriorityByID(ctx context.Context, id int64, priority int) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, updateMessagePriorityByIDSQL, priority, id, priority)
	if err != nil {
		return fmt.Errorf("failed to update message priority: %w", err)
	}
	return nil
}

const deleteMessageByIDSQL = `
UPDATE messages SET delete_at = NOW(), data = ? WHERE id = ? AND delete_at IS NULL
`

func (m *Message) DeleteByID(ctx context.Context, id int64) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, deleteMessageByIDSQL, model.MessageAttr{}, id)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}
	return nil
}

const getMessagesSQL = `
SELECT id, content, priority, status, data, last_heartbeat FROM messages WHERE delete_at IS NULL
`

func (m *Message) List(ctx context.Context) ([]model.Message, error) {
	db := GetDB(ctx)
	rows, err := db.QueryContext(ctx, getMessagesSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}
	defer rows.Close()

	var messages []model.Message
	for rows.Next() {
		var message model.Message
		if err := rows.Scan(&message.MessageID, &message.Content, &message.Priority, &message.Status, &message.Data, &message.LastHeartbeat); err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, message)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred during rows iteration: %w", err)
	}

	return messages, nil
}

const cleanUpSQL = `
DELETE FROM messages WHERE delete_at IS NOT NULL
`

func (m *Message) CleanUp(ctx context.Context) error {
	db := GetDB(ctx)
	_, err := db.ExecContext(ctx, cleanUpSQL)
	if err != nil {
		return fmt.Errorf("failed to clean up messages: %w", err)
	}
	return nil
}

const getCompletedAndFailedMessagesSQL = `
SELECT id, content, priority, status, data, last_heartbeat 
FROM messages 
WHERE (status = ? OR status = ?)
AND last_heartbeat < NOW() - INTERVAL 1 HOUR AND delete_at IS NULL
`

func (m *Message) GetCompletedAndFailed(ctx context.Context) ([]model.Message, error) {
	db := GetDB(ctx)
	rows, err := db.QueryContext(ctx, getCompletedAndFailedMessagesSQL, model.StatusCompleted, model.StatusFailed)
	if err != nil {
		return nil, fmt.Errorf("failed to get completed and failed messages: %w", err)
	}
	defer rows.Close()

	var messages []model.Message
	for rows.Next() {
		var message model.Message
		if err := rows.Scan(&message.MessageID, &message.Content, &message.Priority, &message.Status, &message.Data, &message.LastHeartbeat); err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, message)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred during rows iteration: %w", err)
	}

	return messages, nil
}

const getStaleMessagesSQL = `
SELECT id, content, priority, status, data, last_heartbeat 
FROM messages 
WHERE status = ? 
AND last_heartbeat < NOW() - INTERVAL 1 MINUTE AND delete_at IS NULL
`

func (m *Message) GetStale(ctx context.Context) ([]model.Message, error) {
	db := GetDB(ctx)
	rows, err := db.QueryContext(ctx, getStaleMessagesSQL, model.StatusProcessing)
	if err != nil {
		return nil, fmt.Errorf("failed to get stale messages: %w", err)
	}
	defer rows.Close()

	var messages []model.Message
	for rows.Next() {
		var message model.Message
		if err := rows.Scan(&message.MessageID, &message.Content, &message.Priority, &message.Status, &message.Data, &message.LastHeartbeat); err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, message)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred during rows iteration: %w", err)
	}

	return messages, nil
}

const setStatusAndLeaseSQL = `
UPDATE messages SET status = ?, lease = ? WHERE id = ? AND status = ? AND lease = ? AND delete_at IS NULL
`

func (m *Message) SetStatusAndLease(ctx context.Context, id int64, status model.MessageStatus, lease string) (int64, error) {
	db := GetDB(ctx)
	results, err := db.ExecContext(ctx, setStatusAndLeaseSQL, status, lease, id, model.StatusPending, "")
	if err != nil {
		return 0, fmt.Errorf("failed to set status and lease: %w", err)
	}

	return results.RowsAffected()
}

const setHeartbeatAndDataSQL = `
UPDATE messages SET last_heartbeat = NOW(), data = ? WHERE id = ? AND lease = ? AND status = ? AND delete_at IS NULL
`

func (m *Message) SetHeartbeatAndData(ctx context.Context, id int64, data model.MessageAttr, lease string) (int64, error) {
	db := GetDB(ctx)
	results, err := db.ExecContext(ctx, setHeartbeatAndDataSQL, data, id, lease, model.StatusProcessing)
	if err != nil {
		return 0, fmt.Errorf("failed to set heartbeat and data: %w", err)
	}
	return results.RowsAffected()
}

const setCompletedSQL = `
UPDATE messages SET status = ?, lease = ? WHERE id = ? AND lease = ? AND status = ? AND delete_at IS NULL
`

func (m *Message) SetCompleted(ctx context.Context, id int64, lease string) (int64, error) {
	db := GetDB(ctx)
	results, err := db.ExecContext(ctx, setCompletedSQL, model.StatusCompleted, "", id, lease, model.StatusProcessing)
	if err != nil {
		return 0, fmt.Errorf("failed to set completed: %w", err)
	}
	return results.RowsAffected()
}

const setFailedSQL = `
UPDATE messages SET status = ?, lease = ?, data = ? WHERE id = ? AND lease = ? AND status = ? AND delete_at IS NULL
`

func (m *Message) SetFailed(ctx context.Context, id int64, lease string, data model.MessageAttr) (int64, error) {
	db := GetDB(ctx)
	results, err := db.ExecContext(ctx, setFailedSQL, model.StatusFailed, "", data, id, lease, model.StatusProcessing)
	if err != nil {
		return 0, fmt.Errorf("failed to set status, lease, and data: %w", err)
	}
	return results.RowsAffected()
}

const cancelSQL = `
UPDATE messages SET lease = ?, status = ? WHERE id = ? AND lease = ? AND status = ? AND delete_at IS NULL
`

func (m *Message) Cancel(ctx context.Context, id int64, lease string) (int64, error) {
	db := GetDB(ctx)
	results, err := db.ExecContext(ctx, cancelSQL, "", model.StatusPending, id, lease, model.StatusProcessing)
	if err != nil {
		return 0, fmt.Errorf("failed to set status, lease, and data: %w", err)
	}
	return results.RowsAffected()
}

const resetToPendingSQL = `
UPDATE messages SET status = ?, lease = ? WHERE id = ? AND status = ? AND delete_at IS NULL
`

func (m *Message) ResetToPending(ctx context.Context, id int64) (int64, error) {
	db := GetDB(ctx)
	results, err := db.ExecContext(ctx, resetToPendingSQL, model.StatusPending, "", id, model.StatusProcessing)
	if err != nil {
		return 0, fmt.Errorf("failed to reset status to pending: %w", err)
	}
	return results.RowsAffected()
}
