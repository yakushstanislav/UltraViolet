
COMPOSE := docker compose -f docker-compose.yml
COMPOSE_DEV := docker compose -f docker-compose.yml -f docker-compose.dev.yml

CVE_CATALOG_DUMP ?= ../service-api/deploy/seed/cve-catalog.dump

.PHONY: backup clean cve-catalog-dump dev dev-db down fix-migrations geoip-download logs observability ps up

dev:
	@bash scripts/sync-dev-secrets.sh
	# uv-api/uv-scanner Dockerfiles COPY prebuilt binaries from service-api/bin/
	@$(MAKE) -C ../service-api build-linux
	@$(COMPOSE_DEV) up --build

dev-db:
	@$(COMPOSE_DEV) up -d postgres

fix-migrations:
	@bash scripts/fix-schema-migrations.sh --apply

up: dev

down:
	@$(COMPOSE) down

ps:
	@$(COMPOSE) ps

logs:
	@$(COMPOSE) logs -f

observability:
	@$(COMPOSE) --profile observability up -d

cve-catalog-dump:
	@$(COMPOSE) --profile dump run --rm cve-catalog-dump
	@echo "Wrote ../service-api/deploy/seed/cve-catalog.dump"

backup:
	@$(COMPOSE) --profile backup up -d

geoip-download:
	@bash geoip/download-iplocate-mmdb.sh

clean:
	@$(COMPOSE) down -v
