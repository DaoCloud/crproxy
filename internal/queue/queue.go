package queue

import (
	"container/list"
	"sync"
)

// Queue is a generic Queue implementation.
type Queue[T any] struct {
	base *list.List

	signal chan struct{}
	mut    sync.RWMutex
}

func NewQueue[T any]() *Queue[T] {
	return &Queue[T]{
		base:   list.New(),
		signal: make(chan struct{}, 1),
	}
}

func (q *Queue[T]) Add(item T) {
	q.mut.Lock()
	q.base.PushBack(item)
	q.mut.Unlock()

	// Signal that an item was added.
	select {
	case q.signal <- struct{}{}:
	default:
	}
}

func (q *Queue[T]) Get() (t T, ok bool) {
	q.mut.Lock()
	defer q.mut.Unlock()
	item := q.base.Front()
	if item == nil {
		return t, false
	}
	q.base.Remove(item)
	return item.Value.(T), true
}

func (q *Queue[T]) GetOrWait() T {
	t, ok := q.Get()
	if ok {
		return t
	}

	// Wait for an item to be added.
	for range q.signal {
		t, ok = q.Get()
		if ok {
			return t
		}
	}
	panic("unreachable")
}

func (q *Queue[T]) GetOrWaitWithDone(done <-chan struct{}) (T, bool) {
	t, ok := q.Get()
	if ok {
		return t, ok
	}

	// Wait for an item to be added.
	for {
		select {
		case <-done:
			return t, false
		case <-q.signal:
			t, ok = q.Get()
			if ok {
				return t, true
			}
		}
	}
}

func (q *Queue[T]) Len() int {
	q.mut.RLock()
	defer q.mut.RUnlock()
	return q.base.Len()
}
