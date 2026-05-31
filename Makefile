
GO_CACHE ?= /tmp/uv-go-build
UV_REGISTRY ?= docker.io/ultraviolet
# Production Linux hosts are amd64; keep explicit so Apple Silicon builds do not ship arm64 images.
DOCKER_PLATFORM ?= linux/amd64
VERSION ?=
DRY_RUN ?=

.PHONY: build clean dev dev-db docs-build docs-dev env-down frontend-build lint release release-promote test

build:
	@$(MAKE) -C service-api build

test:
	@cd service-api && GOCACHE=$(GO_CACHE) go test ./...

lint:
	@$(MAKE) -C service-api lint
	@$(MAKE) -C service-frontend lint

frontend-build:
	@$(MAKE) -C service-frontend build

docs-dev:
	@$(MAKE) -C service-documentation-frontend dev

docs-build:
	@$(MAKE) -C service-documentation-frontend build

dev:
	@$(MAKE) -C service-env dev

dev-db:
	@$(MAKE) -C service-env dev-db

env-down:
	@$(MAKE) -C service-env down

clean:
	@$(MAKE) -C service-api clean
	@$(MAKE) -C service-frontend clean
	@$(MAKE) -C service-documentation-frontend clean

release:
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required, e.g. make release VERSION=v0.1.0" >&2; exit 1; fi
	@case "$(VERSION)" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "VERSION must match vMAJOR.MINOR.PATCH (got $(VERSION))" >&2; exit 1;; esac
	@if [ "$(DRY_RUN)" != "1" ]; then \
		git diff --quiet && git diff --cached --quiet || { echo "Working tree is not clean" >&2; exit 1; }; \
		git rev-parse "$(VERSION)" >/dev/null 2>&1 || { echo "Git tag $(VERSION) does not exist" >&2; exit 1; }; \
	fi
	@echo "Building release $(VERSION) → $(UV_REGISTRY) ($(DOCKER_PLATFORM))..."
	@UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) DOCKER_PLATFORM=$(DOCKER_PLATFORM) $(MAKE) -C service-api docker-release
	@UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) DOCKER_PLATFORM=$(DOCKER_PLATFORM) $(MAKE) -C service-frontend docker-release
	@UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) DOCKER_PLATFORM=$(DOCKER_PLATFORM) $(MAKE) -C service-documentation-frontend docker-release
	@if [ "$(DRY_RUN)" != "1" ]; then \
		UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) DOCKER_PLATFORM=$(DOCKER_PLATFORM) $(MAKE) -C service-api docker-push; \
		UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) DOCKER_PLATFORM=$(DOCKER_PLATFORM) $(MAKE) -C service-frontend docker-push; \
		UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) DOCKER_PLATFORM=$(DOCKER_PLATFORM) $(MAKE) -C service-documentation-frontend docker-push; \
	fi
	@VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) DOCKER_PLATFORM=$(DOCKER_PLATFORM) bash service-env/scripts/build-archives.sh
	@echo "Release $(VERSION) complete. Archives in dist/"

release-promote:
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required" >&2; exit 1; fi
	@UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) $(MAKE) -C service-api docker-promote-latest
	@UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) $(MAKE) -C service-frontend docker-promote-latest
	@UV_VERSION=$(VERSION) UV_REGISTRY=$(UV_REGISTRY) $(MAKE) -C service-documentation-frontend docker-promote-latest
	@echo "Promoted $(VERSION) to :latest on $(UV_REGISTRY)"
