# Native plugin example is not cross-platform so do not build it by default
PKGS := $(shell go list ./... | grep -v dummy)
TESTS := $(shell go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./...)
GOLINT := $(GOPATH)/bin/golint
CMD_PATH := cmd


all: build vet lint test

build:
	go build -v $(PKGS)

test:
	go test $(TESTS)

lint: $(GOLINT)
	golint $(PKGS)

vet:
	go vet $(PKGS)

install:
	go install $(PKGS)

clean:
	go clean $(PKGS)

uninstall:
	go clean -i $(PKGS)

dummy-plugin:
	cd plugins/dummy && go build -buildmode=plugin -o dummy.so

$(GOLINT):
	go get -v github.com/golang/lint/golint

.PHONY: all build test lint vet install clean uninstall dummy-plugin
