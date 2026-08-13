package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Event struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

type Hub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{subscribers: make(map[string]map[chan Event]struct{})}
}

func (h *Hub) Publish(userID string, event Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for subscriber := range h.subscribers[userID] {
		select {
		case subscriber <- event:
		default:
		}
	}
}

func (h *Hub) Subscribe(userID string) (<-chan Event, func()) {
	channel := make(chan Event, 16)
	h.mu.Lock()
	if h.subscribers[userID] == nil {
		h.subscribers[userID] = make(map[chan Event]struct{})
	}
	h.subscribers[userID][channel] = struct{}{}
	h.mu.Unlock()
	return channel, func() {
		h.mu.Lock()
		delete(h.subscribers[userID], channel)
		if len(h.subscribers[userID]) == 0 {
			delete(h.subscribers, userID)
		}
		close(channel)
		h.mu.Unlock()
	}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := GetPrincipal(r.Context())
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "authentication_required", "Authentication required", "Sign in to continue.")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		WriteProblem(w, r, http.StatusInternalServerError, "streaming_unavailable", "Streaming unavailable", "This server cannot stream events.")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	events, unsubscribe := h.Subscribe(principal.UserID)
	defer unsubscribe()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-events:
			encoded, err := json.Marshal(event.Data)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", event.ID, event.Type, encoded)
			flusher.Flush()
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
