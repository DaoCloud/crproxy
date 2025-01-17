package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/daocloud/crproxy/queue/dao"
	"github.com/daocloud/crproxy/queue/model"
)

type MessageService struct {
	db         *sql.DB
	messageDao *dao.Message
}

func NewMessageService(db *sql.DB, messageDao *dao.Message) *MessageService {
	return &MessageService{
		db:         db,
		messageDao: messageDao,
	}
}

func (s *MessageService) Create(ctx context.Context, message model.Message) (int64, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.Create(ctx, message)
}

func (s *MessageService) GetByID(ctx context.Context, id int64) (model.Message, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.GetByID(ctx, id)
}

func (s *MessageService) GetByContent(ctx context.Context, content string) (model.Message, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.GetByContent(ctx, content)
}

func (s *MessageService) UpdateByID(ctx context.Context, id int64, message model.Message) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.UpdateByID(ctx, id, message)
}

func (s *MessageService) UpdatePriorityByID(ctx context.Context, id int64, priority int) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.UpdatePriorityByID(ctx, id, priority)
}

func (s *MessageService) DeleteByID(ctx context.Context, id int64) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.DeleteByID(ctx, id)
}

func (s *MessageService) List(ctx context.Context) ([]model.Message, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.List(ctx)
}

func (s *MessageService) Consume(ctx context.Context, id int64, lease string) (model.Message, error) {
	ctx = dao.WithDB(ctx, s.db)

	rowsAffected, err := s.messageDao.SetStatusAndLease(ctx, id, model.StatusProcessing, lease)
	if err != nil {
		return model.Message{}, err
	}

	if rowsAffected == 0 {
		return model.Message{}, fmt.Errorf("no rows affected when consuming message with id %d", id)
	}

	message, err := s.messageDao.GetByID(ctx, id)
	if err != nil {
		return model.Message{}, err
	}
	return message, nil
}

func (s *MessageService) Heartbeat(ctx context.Context, id int64, data model.MessageAttr, lease string) error {
	ctx = dao.WithDB(ctx, s.db)
	rowsAffected, err := s.messageDao.SetHeartbeatAndData(ctx, id, data, lease)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows affected when updating heartbeat for message with id %d", id)
	}
	return nil
}

func (s *MessageService) Completed(ctx context.Context, id int64, lease string) error {
	ctx = dao.WithDB(ctx, s.db)
	rowsAffected, err := s.messageDao.SetCompleted(ctx, id, lease)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows affected when completing message with id %d", id)
	}
	return nil
}

func (s *MessageService) Failed(ctx context.Context, id int64, lease string, data model.MessageAttr) error {
	ctx = dao.WithDB(ctx, s.db)
	rowsAffected, err := s.messageDao.SetFailed(ctx, id, lease, data)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows affected when failing message with id %d", id)
	}
	return nil
}

func (s *MessageService) Cancel(ctx context.Context, id int64, lease string) error {
	ctx = dao.WithDB(ctx, s.db)
	rowsAffected, err := s.messageDao.Cancel(ctx, id, lease)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows affected when failing message with id %d", id)
	}
	return nil
}

func (s *MessageService) CleanUp(ctx context.Context) error {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.CleanUp(ctx)
}

func (s *MessageService) GetCompletedAndFailed(ctx context.Context) ([]model.Message, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.GetCompletedAndFailed(ctx)
}

func (s *MessageService) GetStale(ctx context.Context) ([]model.Message, error) {
	ctx = dao.WithDB(ctx, s.db)
	return s.messageDao.GetStale(ctx)
}

func (s *MessageService) ResetToPending(ctx context.Context, id int64) error {
	ctx = dao.WithDB(ctx, s.db)
	rowsAffected, err := s.messageDao.ResetToPending(ctx, id)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows affected when resetting message with id %d to pending", id)
	}
	return nil
}
