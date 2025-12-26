VERSION ?= "0.2.0-dev"
COMMIT  ?= $(shell git rev-parse --short HEAD)
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT) \
           -X main.buildDate=$(DATE)

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/zkpi ./cmd

.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" ./cmd