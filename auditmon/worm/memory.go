package worm

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// memoryStore is an in-memory ObjectStore for tests.
type memoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// NewMemory returns an in-memory ObjectStore.
func NewMemory() ObjectStore {
	return &memoryStore{objects: make(map[string][]byte)}
}

func (m *memoryStore) Put(key string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := make([]byte, len(body))
	copy(stored, body)
	m.objects[key] = stored
	return nil
}

func (m *memoryStore) List(prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (m *memoryStore) Get(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("worm: object %q: %w", key, ErrNotFound)
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, nil
}
