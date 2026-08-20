
PWD := $(shell pwd)
UV_REGISTRY ?= docker.io/styakush
UV_VERSION ?= dev
DOCKER_PLATFORM ?= linux/amd64
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
UV_MINOR_TAG := $(shell echo "$(UV_VERSION)" | sed -n 's/^v\([0-9]*\.[0-9]*\).*/\1/p')
FRONTEND_IMAGE := uv-frontend

.PHONY: build clean docker docker-push docker-promote-latest docker-release install lint upload
.DEFAULT_GOAL := build

install:
	@echo "Install dependencies..."
	@npm ci
	@echo "Done!"

lint: install
	@echo "Lint..."
	@npm run lint
	@echo "Done!"

build: install
	@echo "Build..."
	@npm run build
	@echo "Done!"

docker: build
	@echo "Build docker image (local tags)..."
	@docker buildx build --platform $(DOCKER_PLATFORM) --load \
		-t $(FRONTEND_IMAGE):$(GIT_HASH) -t $(FRONTEND_IMAGE):latest \
		-f $(PWD)/deploy/Dockerfile $(PWD)
	@echo "Done!"

docker-release: build
	@echo "Build release image $(UV_REGISTRY)/$(FRONTEND_IMAGE):$(UV_VERSION)..."
	@docker buildx build --platform $(DOCKER_PLATFORM) --load \
		-t $(UV_REGISTRY)/$(FRONTEND_IMAGE):$(UV_VERSION) \
		$(if $(UV_MINOR_TAG),-t $(UV_REGISTRY)/$(FRONTEND_IMAGE):$(UV_MINOR_TAG),) \
		-f $(PWD)/deploy/Dockerfile $(PWD)
	@echo "Done!"

docker-push:
	@echo "Push $(UV_REGISTRY)/$(FRONTEND_IMAGE):$(UV_VERSION)..."
	@docker push $(UV_REGISTRY)/$(FRONTEND_IMAGE):$(UV_VERSION)
	@$(if $(UV_MINOR_TAG),docker push $(UV_REGISTRY)/$(FRONTEND_IMAGE):$(UV_MINOR_TAG),)
	@echo "Done!"

docker-promote-latest:
	@echo "Promote $(UV_VERSION) to :latest..."
	@docker tag $(UV_REGISTRY)/$(FRONTEND_IMAGE):$(UV_VERSION) $(UV_REGISTRY)/$(FRONTEND_IMAGE):latest
	@docker push $(UV_REGISTRY)/$(FRONTEND_IMAGE):latest
	@echo "Done!"

upload: docker-release docker-push
	@echo "Upload complete."

clean:
	@echo "Clean..."
	@rm -rf dist node_modules
	@echo "Done!"
