# ==============================================================================
# Packaging make file
# ==============================================================================

# Default target when running `make`
all: local-service-dev


cli-dev:
	echo "==> Run cli dev"
	RUST_BACKTRACE=1 cargo run

local-service-dev:
	echo "==> Run api dev"
	UI_ORIGIN=http://secretpass-local.localhost:3001 \
	RUST_BACKTRACE=1 cargo run -- start

build:
	echo "==> Build Cli"
	cargo build --release
