# ==============================================================================
# Packaging make file
# ==============================================================================

# Default target when running `make`
all: dev

LOCAL_DB_URL=postgres://api:L0calApiPass@localhost:5432/secretpass

create-migration:
	echo "==> Create migration"
	DATABASE_URL=$(LOCAL_DB_URL) sqlx migrate create $(ARGS)

run-migration:
	echo "==> Run migration"
	sqlx migrate run

cloud-dev:
	echo "==> Running local cloud server"
	DATABASE_URL=$(LOCAL_DB_URL) RUST_BACKTRACE=1 cargo run

build:
	echo "==> Build Api"
	cargo build --release
