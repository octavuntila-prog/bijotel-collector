# bijotel-collector — Go OTLP receiver for the BIJOTEL HMAC chain.
#
# All targets run inside Docker (golang:1.22-alpine) so contributors
# don't need Go installed locally. `make local-*` variants exist for
# developers who do.

PKG       := github.com/octavuntila-prog/bijotel-collector
BIN       := bijotel-collector
DOCKER    := docker run --rm -v "$(PWD)":/work -w /work golang:1.22-alpine
DOCKER_SH := $(DOCKER) sh -c

.PHONY: build test docker clean help

help:
	@echo "make build         build a Linux binary in ./bin/ (via Docker)"
	@echo "make test          run unit tests (via Docker)"
	@echo "make docker        build the production OCI image (bijotel-collector:dev)"
	@echo "make clean         remove ./bin/ + test artefacts"
	@echo "make local-build   same as build but assumes host Go is installed"
	@echo "make local-test    same as test but assumes host Go is installed"

build:
	$(DOCKER_SH) "apk add --no-cache git >/dev/null && go build -o ./bin/$(BIN) ./cmd/$(BIN)"

test:
	$(DOCKER_SH) "apk add --no-cache git >/dev/null && go test ./... -v"

docker:
	docker build -t $(BIN):dev .

clean:
	rm -rf ./bin/ ./*.db ./*.db-wal ./*.db-shm

local-build:
	go build -o ./bin/$(BIN) ./cmd/$(BIN)

local-test:
	go test ./... -v
