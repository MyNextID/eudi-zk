VERSION ?= "0.3.0-dev"
COMMIT  ?= $(shell git rev-parse --short HEAD)
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X github.com/mynextid/eudi-zk/server/api.Version=$(VERSION) \
           -X github.com/mynextid/eudi-zk/server/api.Commit=$(COMMIT) \
           -X github.com/mynextid/eudi-zk/server/api.BuildDate=$(DATE)

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/zkpi ./cmd

.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" ./cmd