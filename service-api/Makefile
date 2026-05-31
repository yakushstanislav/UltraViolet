
PWD := $(shell pwd)
ARCH ?= $(shell go env GOARCH)
BUILD_DIR := $(PWD)/bin
CMDS := uv-api uv-scanner
UV_REGISTRY ?= docker.io/ultraviolet
UV_VERSION ?= dev
DOCKER_PLATFORM ?= linux/amd64
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
UV_MINOR_TAG := $(shell echo "$(UV_VERSION)" | sed -n 's/^v\([0-9]*\.[0-9]*\).*/\1/p')
GO_CACHE ?= /tmp/uv-go-build
GOLANGCI_LINT_CACHE ?= /tmp/uv-golangci-lint
OS ?= $(shell go env GOOS)

.PHONY: build build-linux check-quality clean docker docker-push docker-promote-latest docker-release fmt lint setup upload vet
.DEFAULT_GOAL := build

setup:
	@echo "Setup git hooks..."
	@git config core.hooksPath service-api/.githooks
	@echo "Done!"

fmt:
	@echo "Format..."
	@gofmt -w .
	@goimports -w -local github.com/yakushstanislav/UltraViolet .
	@echo "Done!"

vet:
	@echo "Vet..."
	@GOCACHE=$(GO_CACHE) go vet ./...
	@echo "Done!"

lint:
	@echo "Lint..."
	@GOCACHE=$(GO_CACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) golangci-lint run
	@echo "Done!"

check-quality: lint

build:
	@echo "Build $(OS)/$(ARCH)..."
	@$(foreach cmd,$(CMDS),UV_VERSION=$(UV_VERSION) GOCACHE=$(GO_CACHE) APP_NAME=$(cmd) APP_DIR=$(PWD)/cmd/$(cmd) BUILD_DIR=$(BUILD_DIR) OS=$(OS) ARCH=$(ARCH) ./scripts/build.sh || exit;)
	@echo "Done!"

build-linux:
	@echo "Build linux/amd64 binaries..."
	@$(foreach cmd,$(CMDS),UV_VERSION=$(UV_VERSION) GOCACHE=$(GO_CACHE) APP_NAME=$(cmd) APP_DIR=$(PWD)/cmd/$(cmd) BUILD_DIR=$(BUILD_DIR) OS=linux ARCH=amd64 ./scripts/build.sh || exit;)
	@echo "Done!"

docker: build-linux
	@echo "Build docker images (local tags)..."
	@$(foreach cmd,$(CMDS),docker buildx build --platform $(DOCKER_PLATFORM) --load \
		--build-arg APP_NAME=$(cmd) \
		-t $(cmd):$(GIT_HASH) -t $(cmd):latest \
		-f $(PWD)/deploy/Dockerfile $(PWD) || exit;)
	@echo "Done!"

docker-release: build-linux
	@echo "Build release images $(UV_REGISTRY)/*:$(UV_VERSION)..."
	@$(foreach cmd,$(CMDS),docker buildx build --platform $(DOCKER_PLATFORM) --load \
		--build-arg APP_NAME=$(cmd) \
		-t $(UV_REGISTRY)/$(cmd):$(UV_VERSION) \
		$(if $(UV_MINOR_TAG),-t $(UV_REGISTRY)/$(cmd):$(UV_MINOR_TAG),) \
		-f $(PWD)/deploy/Dockerfile $(PWD) || exit;)
	@echo "Done!"

docker-push:
	@echo "Push $(UV_REGISTRY)/*:$(UV_VERSION)..."
	@$(foreach cmd,$(CMDS),docker push $(UV_REGISTRY)/$(cmd):$(UV_VERSION) || exit;)
	@$(if $(UV_MINOR_TAG),$(foreach cmd,$(CMDS),docker push $(UV_REGISTRY)/$(cmd):$(UV_MINOR_TAG) || exit;),)
	@echo "Done!"

docker-promote-latest:
	@echo "Promote $(UV_VERSION) to :latest..."
	@$(foreach cmd,$(CMDS),docker tag $(UV_REGISTRY)/$(cmd):$(UV_VERSION) $(UV_REGISTRY)/$(cmd):latest && \
		docker push $(UV_REGISTRY)/$(cmd):latest || exit;)
	@echo "Done!"

upload: docker-release docker-push
	@echo "Upload complete."

clean:
	@echo "Clean..."
	@rm -rf $(BUILD_DIR)
	@echo "Done!"
