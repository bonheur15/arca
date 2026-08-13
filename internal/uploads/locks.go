package uploads

import "sync"

type lockEntry struct {
	mutex sync.Mutex
	refs  int
}

type keyedLocks struct {
	mutex sync.Mutex
	items map[string]*lockEntry
}

func (l *keyedLocks) lock(key string) func() {
	l.mutex.Lock()
	if l.items == nil {
		l.items = make(map[string]*lockEntry)
	}
	entry := l.items[key]
	if entry == nil {
		entry = &lockEntry{}
		l.items[key] = entry
	}
	entry.refs++
	l.mutex.Unlock()
	entry.mutex.Lock()
	return func() {
		entry.mutex.Unlock()
		l.mutex.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(l.items, key)
		}
		l.mutex.Unlock()
	}
}
