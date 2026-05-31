
PWD := $(shell pwd)
UV_REGISTRY ?= docker.io/ultraviolet
UV_VERSION ?= dev
DOCKER_PLATFORM ?= linux/amd64
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
UV_MINOR_TAG := $(shell echo "$(UV_VERSION)" | sed -n 's/^v\([0-9]*\.[0-9]*\).*/\1/p')
DOCS_IMAGE := uv-documentation

.PHONY: build clean dev docker docker-push docker-promote-latest docker-release install lint preview upload
.DEFAULT_GOAL := build

install:
	@echo "Install dependencies..."
	@npm install --no-audit --no-fund
	@echo "Done!"

lint: install
	@echo "Lint..."
	@echo "(no project-specific lint; VitePress build validates internal links)"
	@echo "Done!"

build: install
	@echo "Build..."
	@npm run build
	@echo "Done!"

dev: install
	@echo "Starting VitePress dev server on http://localhost:5173"
	@npm run dev

preview: build
	@echo "Preview build on http://localhost:4173"
	@npm run preview

docker: build
	@echo "Build docker image (local tags)..."
	@docker buildx build --platform $(DOCKER_PLATFORM) --load \
		-t $(DOCS_IMAGE):$(GIT_HASH) -t $(DOCS_IMAGE):latest \
		-f $(PWD)/deploy/Dockerfile $(PWD)
	@echo "Done!"

docker-release: build
	@echo "Build release image $(UV_REGISTRY)/$(DOCS_IMAGE):$(UV_VERSION)..."
	@docker buildx build --platform $(DOCKER_PLATFORM) --load \
		-t $(UV_REGISTRY)/$(DOCS_IMAGE):$(UV_VERSION) \
		$(if $(UV_MINOR_TAG),-t $(UV_REGISTRY)/$(DOCS_IMAGE):$(UV_MINOR_TAG),) \
		-f $(PWD)/deploy/Dockerfile $(PWD)
	@echo "Done!"

docker-push:
	@echo "Push $(UV_REGISTRY)/$(DOCS_IMAGE):$(UV_VERSION)..."
	@docker push $(UV_REGISTRY)/$(DOCS_IMAGE):$(UV_VERSION)
	@$(if $(UV_MINOR_TAG),docker push $(UV_REGISTRY)/$(DOCS_IMAGE):$(UV_MINOR_TAG),)
	@echo "Done!"

docker-promote-latest:
	@echo "Promote $(UV_VERSION) to :latest..."
	@docker tag $(UV_REGISTRY)/$(DOCS_IMAGE):$(UV_VERSION) $(UV_REGISTRY)/$(DOCS_IMAGE):latest
	@docker push $(UV_REGISTRY)/$(DOCS_IMAGE):latest
	@echo "Done!"

upload: docker-release docker-push
	@echo "Upload complete."

clean:
	@echo "Clean..."
	@rm -rf docs/.vitepress/cache docs/.vitepress/dist node_modules
	@echo "Done!"
