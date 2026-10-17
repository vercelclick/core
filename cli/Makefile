# ==============================================================================
# Packaging make file
# ==============================================================================

# Default target when running `make`
all: api-dev


cli-dev:
	echo "==> Run cli dev"
	RUST_BACKTRACE=1 cargo run --bin spass

local-service-dev:
	echo "==> Run api dev"
	RUST_BACKTRACE=1 cargo run --bin spass-service

build:
	echo "==> Build Cli"
	cargo build --release
