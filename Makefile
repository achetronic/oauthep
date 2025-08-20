# Image URL to use all building/pushing image targets
IMG ?= plugin:latest

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: ## Run tests.
	@go test ./...

GOLANGCI_LINT = $(shell pwd)/bin/golangci-lint
GOLANGCI_LINT_VERSION ?= v1.59.2
golangci-lint:
	@[ -f $(GOLANGCI_LINT) ] || { \
	set -e ;\
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell dirname $(GOLANGCI_LINT)) $(GOLANGCI_LINT_VERSION) ;\
	}

.PHONY: tidy
tidy: ## Runs go mod tidy on the plugin
	@go mod tidy -v

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter & yamllint
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

##@ Build

.PHONY: build
build: ## Build .SO binary.
	@mkdir -p dist
	@version_to_use=$$(grep 'github.com/envoyproxy/envoy' go.mod | awk '{print $$2}' | sed 's/^v//'); \
	echo "Building for Envoy version: $$version_to_use"; \
	go build -buildvcs=false --buildmode=c-shared -v -o dist/liboauthep-dev.so plugin/main.go

PLATFORMS := linux/amd64 linux/arm64

.PHONY: build-all
build-all: check-cross-compilers ## Build .so binaries for all supported Envoy versions and platforms.
	@mkdir -p dist
	@cp go.mod go.mod.backup
	@for version in $(SUPPORTED_ENVOY_VERSIONS); do \
		echo "Building for Envoy $$version..."; \
		go mod edit -require=github.com/envoyproxy/envoy@$$version; \
		go mod tidy; \
		for platform in $(PLATFORMS); do \
			export GOOS=$$(echo $$platform | cut -d'/' -f1); \
			export GOARCH=$$(echo $$platform | cut -d'/' -f2); \
			echo "  - Building for $$GOOS/$$GOARCH"; \
			if [ "$$GOARCH" = "arm64" ]; then \
				CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=$$GOOS GOARCH=$$GOARCH \
				go build -buildvcs=false --buildmode=c-shared -v \
				-o dist/liboauthep-$$GOOS-$$GOARCH-$$version.so plugin/main.go; \
			else \
				CGO_ENABLED=1 GOOS=$$GOOS GOARCH=$$GOARCH \
				go build -buildvcs=false --buildmode=c-shared -v \
				-o dist/liboauthep-$$GOOS-$$GOARCH-$$version.so plugin/main.go; \
			fi; \
		done; \
	done
	@mv go.mod.backup go.mod

.PHONY: check-cross-compilers
check-cross-compilers: ## Check if cross-compilation tools are installed
	@echo "Checking cross-compilation dependencies..."
	@command -v gcc >/dev/null 2>&1 || { echo "❌ gcc not found. Install build-essential."; exit 1; }
	@command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || { \
		echo "❌ aarch64-linux-gnu-gcc not found."; \
		echo "Install with: sudo apt-get install gcc-aarch64-linux-gnu"; \
		echo "Or on macOS: brew install aarch64-elf-gcc"; \
		exit 1; \
	}
	@echo "✅ All cross-compilers found"

.PHONY: install-cross-compilers
install-cross-compilers: ## Install cross-compilation tools (Ubuntu/Debian)
	@echo "Installing cross-compilation tools..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu; \
	elif command -v brew >/dev/null 2>&1; then \
		brew install aarch64-elf-gcc; \
	else \
		echo "❌ Unsupported package manager. Install gcc-aarch64-linux-gnu manually."; \
		exit 1; \
	fi
	@echo "✅ Cross-compilers installed"

.PHONY: generate-dev-config
generate-dev-config: ## Generate development config with absolute path to plugin
	@if [ ! -f "docs/samples/envoy/envoy-config-goext-dev.yaml" ]; then \
		absolute_path="$$(pwd)/dist/liboauthep-dev.so"; \
		echo "Generating dev config for Envoy..."; \
		echo "Plugin path: $$absolute_path"; \
		cp docs/samples/envoy/envoy-config-goext-basic.yaml docs/samples/envoy/envoy-config-goext-dev.yaml; \
		sed -i 's|library_path: ".*"|library_path: "'$$absolute_path'"|g' docs/samples/envoy/envoy-config-goext-dev.yaml; \
		echo "✅ Generated docs/samples/envoy/envoy-config-goext-dev.yaml"; \
	else \
		echo "✅ docs/samples/envoy/envoy-config-goext-dev.yaml already exists"; \
	fi

.PHONY: clean-dev-config
clean-dev-config: ## Remove generated development config
	@rm -f docs/samples/envoy/envoy-config-goext-dev.yaml
	@echo "✅ Removed docs/samples/envoy/envoy-config-goext-dev.yaml"

# For testing, Envoy is defaulted to version declared in go.mod
# This variable can override selected Envoy version, and use another
ENVOY_VERSION ?=

.PHONY: run
run: download-envoy-bins build generate-dev-config ## Run envoy using your plugin from your host
	@if [ -n "$(ENVOY_VERSION)" ]; then \
		version_to_use="$(ENVOY_VERSION)"; \
	else \
		version_to_use=$$(grep 'github.com/envoyproxy/envoy' go.mod | awk '{print $$2}' | sed 's/^v//'); \
	fi; \
	echo "Using Envoy version: $$version_to_use"; \
	$(LOCALBIN)/envoy-$$version_to_use -c ./docs/samples/envoy/envoy-config-goext-dev.yaml --concurrency 2 --log-format '%v'

.PHONY: docker-build-amd64
docker-build-amd64: build-all ## Build docker image with amd64 plugins only
	@mkdir -p dist-amd64
	@cp dist/*-linux-amd64-*.so dist-amd64/
	$(CONTAINER_TOOL) build -t ${IMG}-amd64 . -f Dockerfile --build-arg DIST_DIR=dist-amd64

.PHONY: docker-build-arm64
docker-build-arm64: build-all ## Build docker image with arm64 plugins only
	@mkdir -p dist-arm64
	@cp dist/*-linux-arm64-*.so dist-arm64/
	$(CONTAINER_TOOL) build -t ${IMG}-arm64 . -f Dockerfile --build-arg DIST_DIR=dist-arm64

.PHONY: docker-build-all
docker-build-all: docker-build-amd64 docker-build-arm64 ## Build both architecture images

.PHONY: docker-push-all
docker-push-all: ## Push both architecture images
	$(CONTAINER_TOOL) push ${IMG}-amd64
	$(CONTAINER_TOOL) push ${IMG}-arm64

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
ENVOY ?= $(LOCALBIN)/envoy

## Tool Versions

## Supported versions of Envoy for `make build-all` step.
## This will impact on build-time
## History: https://www.envoyproxy.io/docs/envoy/latest/version_history/version_history
SUPPORTED_ENVOY_VERSIONS := v1.34.0 v1.34.1 v1.34.2 v1.34.3 v1.34.4 v1.34.5 v1.35.0 v1.35.1

.PHONY: download-envoy-bins
download-envoy-bins: $(LOCALBIN) ## Download all supported Envoy versions
	@for version in $(SUPPORTED_ENVOY_VERSIONS); do \
		version_clean=$$(echo $$version | sed 's/^v//'); \
		binary_name="envoy-contrib-$$version_clean-linux-x86_64"; \
		target_name="$(LOCALBIN)/envoy-$$version_clean"; \
		if [ ! -f "$$target_name" ]; then \
			echo "Downloading Envoy $$version_clean..."; \
			wget --timestamping --quiet \
				"https://github.com/envoyproxy/envoy/releases/download/$$version/$$binary_name" \
				-P $(LOCALBIN); \
			mv "$(LOCALBIN)/$$binary_name" "$$target_name"; \
			chmod +x "$$target_name"; \
			echo "✅ Downloaded $$target_name"; \
		else \
			echo "✅ $$target_name already exists"; \
		fi; \
	done
