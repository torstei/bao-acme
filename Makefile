BINARY  := bao-acme
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
LDFLAGS := -s -w -X github.com/torstei/bao-acme/internal/backend.Version=$(VERSION)

.PHONY: build test integration vet fmt dev clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test -race ./...

integration:
	go test -tags integration -count=1 -v ./integration/

vet:
	go vet -tags integration ./...
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

fmt:
	gofmt -w .

dev: build
	./scripts/dev.sh

clean:
	rm -rf bin
