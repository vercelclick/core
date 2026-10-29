# ==============================================================================
# Packaging make file
# ==============================================================================

# Default target when running `make`
all: help

# Shared configuration
WASM_TARGET    ?= web


web-local:
	$(MAKE) -C ./web prod-local

web-cloud:
	$(MAKE) -C ./web prod-cloud

export-api-types:
	$(MAKE) -C ./api export-types

cli-dev:
	@echo "==> Running cli dev"
	$(MAKE) -C ./cli dev

# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------
clean:
	@echo "==> Cleaning generated WASM packages and target directory..."
	rm -rf web/pkg web/pkg-local web/pkg-sandbox
	cargo clean

infra:
	@echo "==> Starting docker for DB and Cache"
	docker compose .

tag:
	@echo "==> Tagging commit with current package version"
	CURRENT_VERSION=$$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version')
	cargo bump $$CURRENT_VERSION patch --build --git-tag
	cd ../core && cargo bump $$CURRENT_VERSION patch --build --git-tag
	UPDATED_VERSION=$$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version')
	cd ../web-app && git tag $$UPDATED_VERSION

# ------------------------------------------------------------------------------
# Help
# ------------------------------------------------------------------------------
help:
	@echo "Usage:"
	@echo "  make web-local      Build WASM package for cli local storage usage (web/pkg-local/)"
	@echo "  make web-cloud      Build WASM package for cloud service usage (web/pkg-cloud/)"
	@echo "  make clean    		 Remove all built WASM artifacts and cargo cache"