BINARY := tunneld
PKG := ./cmd/tunneld
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/Dankular/Tunneld/internal/version.Version=$(VERSION) \
           -X github.com/Dankular/Tunneld/internal/version.Commit=$(COMMIT) \
           -X github.com/Dankular/Tunneld/internal/version.Date=$(DATE)

.PHONY: build test vet fmt fmt-check lint clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

lint: fmt-check vet test

clean:
	rm -rf bin
