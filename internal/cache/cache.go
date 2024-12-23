package cache

import (
	"sync"
	"time"

	"github.com/daocloud/crproxy/internal/heap"
)

type Cache[K comparable, T any] struct {
	mu   sync.RWMutex
	data map[K]T
	heap *heap.Heap[int64, K]
}

func NewCache[K comparable, T any]() *Cache[K, T] {
	return &Cache[K, T]{
		data: map[K]T{},
		heap: heap.NewHeap[int64, K](),
	}
}

func (c *Cache[K, T]) Set(key K, value T, ttl time.Duration) {
	expiry := time.Now().Add(ttl).Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
	c.heap.Push(expiry, key)
}

func (c *Cache[K, T]) Get(key K) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.data[key]
	return item, ok
}

func (c *Cache[K, T]) Evict() {
	c.mu.Lock()
	defer c.mu.Unlock()
	currentTime := time.Now().Unix()
	for c.heap.Len() > 0 {
		expiry, key, ok := c.heap.Peek()
		if !ok || expiry > currentTime {
			break
		}
		c.heap.Pop()
		delete(c.data, key)
	}
}
