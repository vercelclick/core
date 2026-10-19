# ==============================================================================
# Packaging make file
# ==============================================================================

# Default target when running `make`
all: install build


local-dev:
	echo "==> Run local UI"
	BACKEND_URL=http://secretpass.localhost:20206 bun dev


cloud-dev:
	echo "==> Run cloud UI"
	BACKEND_URL=http://secretpasscloud.localhost:8080 bun dev

install:
	echo "==> Install npm packages"
	bun install

build:
	echo "==> Build bundled UI"
	bun run build
