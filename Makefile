# ==============================================================================
# Packaging make file
# ==============================================================================

.SILENT:

# Default target when running `make`
all: help

# Shared configuration
WASM_TARGET    ?= web
RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))


cloud-run-dev:
	echo "==> Running local cloud server"
	export $$(cat .env | xargs) && cargo run -p secretpass-cloud

local-run-dev:
	@echo "==> Run api dev"
	RUST_BACKTRACE=1 cargo run -p secretpass-local --bin spass -- local start --foreground

db-export-url:
	export DATABASE_URL=postgres://api:L0calApiPass@localhost:5432/secretpass

migration-create:
	@echo "==> Create migration"
	sqlx migrate add --reversible $(RUN_ARGS)

migration-up:
	@echo "==> Run migrations up"
	sqlx migrate run

migration-down:
	@echo "==> Run migration down"
	sqlx migrate revert


wasm-add-target:
	@echo "==> add wasm target"
	# This version must be matched with the version installed in cargo.toml
	cargo install wasm-bindgen-cli --version 0.2.130
	rustup target add wasm32-unknown-unknown


wasm-build-dev:
	@echo "==> Building WASM for development"
	rm -r ../web-app/src/core || echo ""
	RUSTFLAGS='--cfg=web_sys_unstable_apis' \
	cargo rustc -p secretpass-wasm --crate-type cdylib --target wasm32-unknown-unknown
	wasm-bindgen \
      target/wasm32-unknown-unknown/debug/secretpass_wasm.wasm \
      --target bundler \
      --out-name index \
      --out-dir ../web-app/src/core

	./.scripts/export-types


wasm-build-prod:
	@echo "==> Building WASM for production"
	rm -r ../web-app/src/core || echo ""
	rm -r ../web-app/src/core
	RP_ID="vault.vercel.click" \
	RUSTFLAGS='--cfg=web_sys_unstable_apis' \
	cargo rustc -p secretpass-wasm --release --crate-type cdylib --target wasm32-unknown-unknown
	wasm-bindgen \
	  target/wasm32-unknown-unknown/release/secretpass_wasm.wasm \
	  --target bundler \
      --out-name index \
	  --out-dir ../web-app/src/core

	./.scripts/export-types


# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------
clean:
	@echo "==> Cleaning generated WASM packages and target directory..."
	rm -rf ../web-app/src/core
	rm -rf ../web-app/src/api-types
	cargo clean

infra:
	@echo "==> Starting docker for DB and Cache"
	docker compose .


# ------------------------------------------------------------------------------
# Help
# ------------------------------------------------------------------------------
help:
	@echo "Usage:"
	@echo "  make web-local      Build WASM package for cli local storage usage (web/pkg-local/)"
	@echo "  make web-cloud      Build WASM package for cloud service usage (web/pkg-cloud/)"
	@echo "  make clean    		 Remove all built WASM artifacts and cargo cache"