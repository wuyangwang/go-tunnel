// Package logutil provides a small rate limiter for repeated warnings.
package logutil

import (
	"log/slog"
	"sync"
	"time"
)

// RateLimiter logs the first occurrence of each message immediately,
// then counts further occurrences and emits at most one summary per
// interval. Each distinct message has its own counter.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	entries  map[string]*entry
}

type entry struct {
	last    time.Time
	pending int
}

// New creates a RateLimiter with the given summary interval.
func New(interval time.Duration) *RateLimiter {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &RateLimiter{
		interval: interval,
		entries:  make(map[string]*entry),
	}
}

// Record logs msg at Warn level, rate-limited. Repeated calls within the
// interval are counted and reported via the "suppressed" attribute.
func (r *RateLimiter) Record(log *slog.Logger, msg string, args ...any) {
	r.mu.Lock()
	e := r.entries[msg]
	if e == nil {
		e = &entry{}
		r.entries[msg] = e
	}
	e.pending++
	now := time.Now()
	if !e.last.IsZero() && now.Sub(e.last) < r.interval {
		r.mu.Unlock()
		return
	}
	suppressed := e.pending - 1
	e.pending = 0
	e.last = now
	r.mu.Unlock()

	if suppressed > 0 {
		withCount := make([]any, 0, len(args)+2)
		withCount = append(withCount, args...)
		withCount = append(withCount, "suppressed", suppressed)
		args = withCount
	}
	log.Warn(msg, args...)
}

// Reset clears the counter for msg so the next occurrence logs
// immediately again. It reports whether there were pending events.
func (r *RateLimiter) Reset(msg string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[msg]
	delete(r.entries, msg)
	return ok && e.pending > 0
}
