package queue

import (
	"sort"
	"sync"
)

type index struct {
	doneChannel chan struct{}
	weight      int
	soon        bool
}

type WeightQueue[T comparable] struct {
	queue  *Queue[T]
	queues map[int]*Queue[T]
	orders []int

	index  map[T]index
	signal chan struct{}
	mut    sync.RWMutex
}

func NewWeightQueue[T comparable]() *WeightQueue[T] {
	q := &WeightQueue[T]{
		queue:  NewQueue[T](),
		queues: map[int]*Queue[T]{},
		signal: make(chan struct{}, 1),
		index:  map[T]index{},
	}
	return q
}

func (q *WeightQueue[T]) addWeight(item T, weight int) {
	if q.queues[weight] == nil {
		q.queues[weight] = NewQueue[T]()
	}
	q.queues[weight].Add(item)
}

func (q *WeightQueue[T]) AddWeight(item T, weight int) <-chan struct{} {
	if weight == 0 {
		weight = 1
	}

	q.mut.Lock()

	ch, ok := q.index[item]
	if !ok {
		ch.doneChannel = make(chan struct{})
		ch.weight = weight
		q.index[item] = ch

		q.addWeight(item, weight)
	} else if !ch.soon && ch.weight < weight {
		q.queues[ch.weight].Remove(item)
		q.addWeight(item, weight)
	}

	q.mut.Unlock()

	select {
	case q.signal <- struct{}{}:
	default:
	}

	return ch.doneChannel
}

func (q *WeightQueue[T]) step() bool {
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

			index, ok := q.index[t]
			if ok {
				index.soon = true
				q.index[t] = index
			}

			q.queue.Add(t)
			added = true
		}
	}
	return added
}

func (q *WeightQueue[T]) get() (T, int, bool) {
	t, ok := q.queue.Get()
	if ok {
		return t, q.index[t].weight, ok
	}

	if q.step() {
		t, ok := q.queue.Get()
		if ok {
			return t, q.index[t].weight, ok
		}
	}
	return t, 0, false
}

func (q *WeightQueue[T]) Get() (T, int, func(), bool) {
	t, weight, ok := q.get()
	if !ok {
		return t, 0, nil, false
	}

	fun := func() {
		q.mut.Lock()
		defer q.mut.Unlock()
		ch, ok := q.index[t]
		if ok {
			close(ch.doneChannel)
			delete(q.index, t)
		}
	}
	return t, weight, fun, true
}

func (q *WeightQueue[T]) GetOrWaitWithDone(done <-chan struct{}) (T, int, func(), bool) {
	t, weight, finish, ok := q.Get()
	if ok {
		return t, weight, finish, ok
	}

	// Wait for an item to be added.
	for {
		select {
		case <-done:
			return t, 0, finish, false
		case <-q.signal:
			t, weight, finish, ok = q.Get()
			if ok {
				return t, weight, finish, true
			}
		}
	}
}

func (q *WeightQueue[T]) Len() int {
	size := q.queue.Len()

	q.mut.RLock()
	defer q.mut.RUnlock()
	for _, queue := range q.queues {
		size += queue.Len()
	}
	return size
}
