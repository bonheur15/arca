package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%v; retry after %s", ErrRateLimited, e.RetryAfter.Round(time.Second))
}

func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type AttemptLimiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, time.Duration)
}

// MemoryLimiter provides per-process, bounded login protection in addition to
// WorkOS limits. It is intentionally not a distributed limiter because Arca v1
// permits only one process per instance.
type MemoryLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	now      func() time.Time
}

func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{attempts: make(map[string][]time.Time), now: time.Now}
}

func (l *MemoryLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, time.Duration) {
	if key == "" || limit <= 0 || window <= 0 {
		return true, 0
	}
	now := l.now()
	cutoff := now.Add(-window)
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := l.attempts[key]
	first := 0
	for first < len(entries) && !entries[first].After(cutoff) {
		first++
	}
	entries = append(entries[:0], entries[first:]...)
	if len(entries) >= limit {
		retry := entries[0].Add(window).Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		l.attempts[key] = entries
		return false, retry
	}
	entries = append(entries, now)
	l.attempts[key] = entries
	if len(l.attempts) > 10_000 {
		for candidate, values := range l.attempts {
			if len(values) == 0 || !values[len(values)-1].After(cutoff) {
				delete(l.attempts, candidate)
			}
		}
	}
	return true, 0
}
