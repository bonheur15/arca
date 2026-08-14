SHELL := /bin/sh
PNPM ?= pnpm
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILT_AT ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.builtAt=$(BUILT_AT)

.PHONY: all generate install-web test test-go test-web build-web build dev clean check

all: check build

generate:
	mkdir -p internal/apitypes
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.5.0 --config api/oapi-codegen.yaml api/openapi.yaml
	cd web && $(PNPM) exec openapi-typescript ../api/openapi.yaml --output src/api/schema.generated.ts

install-web:
	cd web && $(PNPM) install --frozen-lockfile

test-go:
	go test -race ./...

test-web:
	cd web && $(PNPM) test

test: test-go test-web

build-web:
	cd web && $(PNPM) build

build: build-web
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/arca-linux-amd64 ./cmd/arca

dev:
	go run ./cmd/arca serve --listen 127.0.0.1:8080 --data-dir ./arca-data-dev

check: generate
	git diff --exit-code -- internal/apitypes/openapi.generated.go web/src/api/schema.generated.ts
	go vet ./...
	go test ./...
	cd web && $(PNPM) typecheck && $(PNPM) test && $(PNPM) build
	git diff --check

clean:
	rm -f bin/arca-linux-amd64
