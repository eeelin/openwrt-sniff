package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/eeelin/openwrt-sniff/internal/capture"
	"github.com/eeelin/openwrt-sniff/internal/flow"
	webassets "github.com/eeelin/openwrt-sniff/web"
)

type server struct {
	store   *flow.Store
	capture *capture.Manager
	version string
	static  http.Handler
}

func New(store *flow.Store, manager *capture.Manager, version string) http.Handler {
	dist, _ := fs.Sub(webassets.Dist, "dist")
	s := &server{store: store, capture: manager, version: version, static: http.FileServer(http.FS(dist))}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/flows", s.flows)
	mux.HandleFunc("POST /api/v1/capture/start", s.start)
	mux.HandleFunc("POST /api/v1/capture/stop", s.stop)
	mux.HandleFunc("DELETE /api/v1/flows", s.clear)
	mux.HandleFunc("GET /api/v1/events", s.events)
	mux.HandleFunc("/", s.frontend)
	return mux
}

func (s *server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"version": s.version, "capture": s.capture.Status(), "flow_count": len(s.store.Snapshot()), "event_drops": s.store.Dropped()})
}
func (s *server) flows(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"flows": s.store.Snapshot()})
}
func (s *server) start(w http.ResponseWriter, _ *http.Request) {
	if err := s.capture.Start(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.status(w, nil)
}
func (s *server) stop(w http.ResponseWriter, _ *http.Request) { s.capture.Stop(); s.status(w, nil) }
func (s *server) clear(w http.ResponseWriter, _ *http.Request) {
	s.store.Clear()
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	events, cancel := s.store.Subscribe()
	defer func() {
		cancel()
		time.AfterFunc(30*time.Second, func() {
			if s.store.SubscriberCount() == 0 {
				s.capture.Stop()
			}
		})
	}()
	_ = wsJSON(ctx, c, map[string]any{"type": "snapshot", "flows": s.store.Snapshot()})
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			if wsJSON(ctx, c, event) != nil {
				return
			}
		}
	}
}

func (s *server) frontend(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != "/" {
		if _, err := fs.Stat(webassets.Dist, "dist"+r.URL.Path); err != nil {
			r.URL.Path = "/"
		}
	}
	s.static.ServeHTTP(w, r)
}
func wsJSON(ctx context.Context, c *websocket.Conn, value any) error {
	data, _ := json.Marshal(value)
	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return c.Write(writeCtx, websocket.MessageText, data)
}
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
