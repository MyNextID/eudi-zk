VERSION ?= "0.1.2-dev"
COMMIT  ?= $(shell git rev-parse --short HEAD)
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT) \
           -X main.buildDate=$(DATE)

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/zkpi ./server

.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" ./server