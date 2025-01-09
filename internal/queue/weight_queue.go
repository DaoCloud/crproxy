package queue

import (
	"sort"
	"sync"
)

type Queue[T comparable] struct {
	queue  *queue[T]
	queues map[int]*queue[T]
	orders []int

	doneChannel map[T]chan struct{}
	signal      chan struct{}
	mut         sync.RWMutex
}

func NewQueue[T comparable]() *Queue[T] {
	q := &Queue[T]{
		queue:       newQueue[T](),
		queues:      map[int]*queue[T]{},
		signal:      make(chan struct{}, 1),
		doneChannel: map[T]chan struct{}{},
	}
	return q
}

func (q *Queue[T]) AddWeight(item T, weight int) <-chan struct{} {
	if weight == 0 {
		weight = 1
	}

	q.mut.Lock()

	if weight < 0 {
		q.queue.Add(item)
	} else {
		if q.queues[weight] == nil {
			q.queues[weight] = newQueue[T]()
		}
		q.queues[weight].Add(item)
	}

	ch, ok := q.doneChannel[item]
	if !ok {
		ch = make(chan struct{})
		q.doneChannel[item] = ch
	}
	q.mut.Unlock()

	select {
	case q.signal <- struct{}{}:
	default:
	}

	return ch
}

func (q *Queue[T]) step() bool {
	q.mut.Lock()
	defer q.mut.Unlock()

	// Check if the orders slice is out of sync with the queues map
	if len(q.orders) != len(q.queues) {
		orders := make([]int, 0, len(q.queues))
		for k := range q.queues {
			orders = append(orders, k)
		}
		sort.Ints(orders)
		q.orders = orders
	}

	var added bool
	for i := len(q.orders) - 1; i >= 0; i-- {
		weight := q.orders[i]
		queue := q.queues[weight]
		times := weight
		for j := 0; j != times; j++ {
			t, ok := queue.Get()
			if !ok {
				break
			}

			q.queue.Add(t)
			added = true
		}
	}
	return added
}

func (q *Queue[T]) get() (T, bool) {
	t, ok := q.queue.Get()
	if ok {
		return t, ok
	}

	if q.step() {
		t, ok := q.queue.Get()
		if ok {
			return t, ok
		}
	}
	return t, false
}

func (q *Queue[T]) Get() (T, func(), bool) {
	t, ok := q.get()
	if !ok {
		return t, nil, false
	}

	fun := func() {
		q.mut.Lock()
		defer q.mut.Unlock()
		ch, ok := q.doneChannel[t]
		if ok {
			close(ch)
			delete(q.doneChannel, t)
		}
	}
	return t, fun, true
}

func (q *Queue[T]) GetOrWaitWithDone(done <-chan struct{}) (T, func(), bool) {
	t, finish, ok := q.Get()
	if ok {
		return t, finish, ok
	}

	// Wait for an item to be added.
	for {
		select {
		case <-done:
			return t, finish, false
		case <-q.signal:
			t, finish, ok = q.Get()
			if ok {
				return t, finish, true
			}
		}
	}
}

func (q *Queue[T]) Len() int {
	size := q.queue.Len()

	q.mut.RLock()
	defer q.mut.RUnlock()
	for _, queue := range q.queues {
		size += queue.Len()
	}
	return size
}
