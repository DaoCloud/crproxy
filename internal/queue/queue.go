package queue

import (
	"container/list"
	"sync"
)

// Queue is a generic Queue implementation.
type Queue[T comparable] struct {
	base *list.List

	index map[T]*list.Element

	signal chan struct{}
	mut    sync.RWMutex
}

func NewQueue[T comparable]() *Queue[T] {
	return &Queue[T]{
		base:   list.New(),
		index:  map[T]*list.Element{},
		signal: make(chan struct{}, 1),
	}
}

func (q *Queue[T]) Add(item T) {
	q.mut.Lock()
	element := q.base.PushBack(item)
	q.index[item] = element
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
	t = item.Value.(T)
	delete(q.index, t)
	return t, true
}

func (q *Queue[T]) Remove(item T) bool {
	q.mut.Lock()
	defer q.mut.Unlock()
	if element, exists := q.index[item]; exists {
		q.base.Remove(element)
		delete(q.index, item)
		return true
	}
	return false
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
