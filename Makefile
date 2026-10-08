.PHONY: frontend build test clean

VERSION ?= dev

frontend:
	cd web && npm ci && npm run build

build: frontend
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/openwrt-sniff ./cmd/openwrt-sniff

test:
	go test ./cmd/... ./internal/... ./web
	cd web && npm run build

clean:
	rm -rf dist web/dist/assets web/node_modules

