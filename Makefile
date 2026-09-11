.PHONY: build test race lint security clean

VERSION ?= dev

build:
	mkdir -p bin
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/passman ./cmd/passman

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

security:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
	go run github.com/securego/gosec/v2/cmd/gosec@v2.22.8 ./...

clean:
	go clean
