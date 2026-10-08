package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eeelin/openwrt-sniff/internal/api"
	"github.com/eeelin/openwrt-sniff/internal/capture"
	"github.com/eeelin/openwrt-sniff/internal/flow"
)

var version = "dev"

func main() {
	var listen, interfaces string
	var window time.Duration
	var maxFlows, maxStream int
	flag.StringVar(&listen, "listen", "0.0.0.0:8088", "HTTP listen address")
	flag.StringVar(&interfaces, "interfaces", "br-lan", "comma separated capture interfaces")
	flag.DurationVar(&window, "window", 5*time.Minute, "in-memory observation window")
	flag.IntVar(&maxFlows, "max-flows", 4096, "maximum flow records")
	flag.IntVar(&maxStream, "max-stream-bytes", 16384, "maximum TCP bytes retained per flow")
	flag.Parse()

	store := flow.NewStore(maxFlows, window)
	manager := capture.NewManager(split(interfaces), maxStream, store)
	handler := api.New(store, manager, version)
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Printf("openwrt-sniff %s listening on %s", version, listen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()
	<-ctx.Done()
	manager.Stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
}

func split(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
