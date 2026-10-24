# ==============================================================================
# Packaging make file
# ==============================================================================

RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Default target when running `make`
all: cloud-service-dev

LOCAL_DB_URL=postgres://api:L0calApiPass@localhost:5432/secretpass

migration-create:
	echo "==> Create migration"
	DATABASE_URL=$(LOCAL_DB_URL) sqlx migrate add --reversible $(RUN_ARGS)

migration-up:
	echo "==> Run migration"
	DATABASE_URL=$(LOCAL_DB_URL) sqlx migrate run

migration-down:
	echo "==> Run migration"
	DATABASE_URL=$(LOCAL_DB_URL) sqlx migrate revert

cloud-service-dev:
	echo "==> Running local cloud server"
	DATABASE_URL=$(LOCAL_DB_URL) \
	UI_ORIGIN=http://secretpass-cloud.localhost:3002 \
	RUST_BACKTRACE=1 cargo run

build:
	echo "==> Build Api"
	cargo build --release
