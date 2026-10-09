package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
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

func New(store *flow.Store, manager *capture.Manager, version, authToken string) http.Handler {
	dist, _ := fs.Sub(webassets.Dist, "dist")
	s := &server{store: store, capture: manager, version: version, static: http.FileServer(http.FS(dist))}
	auth := newAuthenticator(authToken)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", auth.login)
	mux.HandleFunc("POST /api/v1/auth/logout", auth.logout)
	mux.HandleFunc("GET /api/v1/auth/session", auth.session)
	mux.Handle("GET /api/v1/status", auth.protect(http.HandlerFunc(s.status)))
	mux.Handle("GET /api/v1/flows", auth.protect(http.HandlerFunc(s.flows)))
	mux.Handle("POST /api/v1/capture/start", auth.protect(http.HandlerFunc(s.start)))
	mux.Handle("POST /api/v1/capture/stop", auth.protect(http.HandlerFunc(s.stop)))
	mux.Handle("DELETE /api/v1/flows", auth.protect(http.HandlerFunc(s.clear)))
	mux.Handle("POST /api/v1/debug/capture/start", auth.protect(http.HandlerFunc(s.debugStart)))
	mux.Handle("POST /api/v1/debug/capture/stop", auth.protect(http.HandlerFunc(s.debugStop)))
	mux.Handle("POST /api/v1/debug/capture.pcap", auth.protect(http.HandlerFunc(s.debugDownload)))
	mux.Handle("GET /api/v1/events", auth.protect(http.HandlerFunc(s.events)))
	mux.HandleFunc("/", s.frontend)
	return securityHeaders(mux)
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

func (s *server) debugStart(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Source, Destination string
		Port                uint16
	}
	if r.ContentLength != 0 {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid debug capture request", http.StatusBadRequest)
			return
		}
	}
	options := capture.DebugCaptureOptions{Port: request.Port}
	var err error
	if request.Source != "" {
		options.Source, err = netip.ParseAddr(request.Source)
	}
	if err == nil && request.Destination != "" {
		options.Destination, err = netip.ParseAddr(request.Destination)
	}
	if err != nil {
		http.Error(w, "invalid debug capture address", http.StatusBadRequest)
		return
	}
	if err := s.capture.StartDebugCapture(options); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.status(w, nil)
}

func (s *server) debugStop(w http.ResponseWriter, _ *http.Request) {
	s.capture.StopDebugCapture()
	s.status(w, nil)
}

func (s *server) debugDownload(w http.ResponseWriter, _ *http.Request) {
	data, err := s.capture.TakeDebugCapture()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="sniffd-debug.pcap"`)
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	_, _ = w.Write(data)
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
