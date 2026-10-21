# ==============================================================================
# Packaging make file
# ==============================================================================

# Default target when running `make`
all: help



add-target:
	@echo "==> add wasm target"
	rustup target add wasm32-unknown-unknown


dev-local:
	$(MAKE) add-target
	@echo "==> Building WASM for dev server usage"
	WEBAUTH_RP_ID="secretpass-local.localhost" \
	WEBAUTH_RP_ORIGIN="http://secretpass-local.localhost:3001" \
	WEBAUTH_RP_ENTITY="Secretpass Dev Local" \
	RUSTFLAGS='--cfg=web_sys_unstable_apis' \
	cargo rustc -p web --release --crate-type cdylib --target wasm32-unknown-unknown
	wasm-bindgen \
      ../target/wasm32-unknown-unknown/release/web.wasm \
      --target web \
      --out-dir ../../web-app/src/core


dev-cloud:
	$(MAKE) add-target
	@echo "==> Building WASM for usage"
	WEBAUTH_RP_ID="secretpass-cloud.localhost" \
	WEBAUTH_RP_ORIGIN="http://secretpass-cloud.localhost:3002" \
	WEBAUTH_RP_ENTITY="Secretpass Dev Cloud" \
	RUSTFLAGS='--cfg=web_sys_unstable_apis' \
	cargo rustc -p web --release --crate-type cdylib --target wasm32-unknown-unknown
	wasm-bindgen \
      ../target/wasm32-unknown-unknown/release/web.wasm \
      --target web \
      --out-dir ../../web-app/src/core


prod-cloud:
	$(MAKE) add-target
	@echo "==> Building WASM for cloud usage"
	WEBAUTH_RP_ID="cloud.secretpass.cloud" \
	WEBAUTH_RP_ORIGIN="https://cloud.secretpass.cloud" \
	WEBAUTH_RP_ENTITY="Secretpass Cloud" \
	RUSTFLAGS='--cfg=web_sys_unstable_apis' \
	cargo rustc -p web --release --crate-type cdylib --target wasm32-unknown-unknown
	wasm-bindgen \
	  ../target/wasm32-unknown-unknown/release/web.wasm \
	  --target web \
	  --out-dir ../web-app/src/core


prod-cloud:
	$(MAKE) add-target
	@echo "==> Building WASM for cloud usage"
	WEBAUTH_RP_ID="local.secretpass.cloud" \
	WEBAUTH_RP_ORIGIN="https://local.secretpass.cloud" \
	WEBAUTH_RP_ENTITY="Secretpass Local" \
	RUSTFLAGS='--cfg=web_sys_unstable_apis' \
	cargo rustc -p web --release --crate-type cdylib --target wasm32-unknown-unknown
	wasm-bindgen \
	  ../target/wasm32-unknown-unknown/release/web.wasm \
	  --target web \
	  --out-dir ../web-app/src/core


# ------------------------------------------------------------------------------
# Help
# ------------------------------------------------------------------------------
help:
	@echo "Usage:"
	@echo "  local      Build WASM package for cli local storage usage"
	@echo "  cloud      Build WASM package for cloud service usage"
