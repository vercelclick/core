# ==============================================================================
# Packaging make file
# ==============================================================================

# Default target when running `make`
all: dev


dev:
	echo "==> Run cli dev"
	RUST_BACKTRACE=1 cargo run -- --project-dir ../

build:
	echo "==> Build Cli"
	cargo build --release


export-types:
	echo "==> Exporting shared types"
	cargo test export_bindings