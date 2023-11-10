DOCKER := $(shell which docker)
CUR_DIR := $(shell pwd)
CUR_BASENAME := $(shell basename $(CUR_DIR))
# Native arch
BUILDARCH := $(shell uname -m)
OPTIMIZER_IMAGE_NAME := "babylonchain/rust-optimizer-$(BUILDARCH)"
OPTIMIZER_IMAGE_TAG := "0.0.1"

build:
	@cargo build

test-ci: lint test ## Run all the CI checks locally (in your actual toolchain)

lint: ## Check whether the code is formatted correctly
	@cargo fmt --all -- --check
	@cargo check

test:
	@cargo test --lib

integration-test:
	@cargo test --test integration

schema:
	@cargo run schema
	
proto-gen:
	@echo "Generating Protobuf files"
	@bash ./scripts/protocgen.sh

rust-optimizer-image:
	@$(DOCKER) build -t $(OPTIMIZER_IMAGE_NAME):$(OPTIMIZER_IMAGE_TAG) -f ./Dockerfile-$(BUILDARCH) .

build-optimized:
	if [ -z $$(docker images -q $(OPTIMIZER_IMAGE_NAME)) ]; then \
        make rust-optimizer-image; \
    fi
	$(DOCKER) run --rm -v "$(CUR_DIR)":/code \
		--mount type=volume,source="$(CUR_BASENAME)_cache",target=/code/target \
		--mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
		$(OPTIMIZER_IMAGE_NAME):$(OPTIMIZER_IMAGE_TAG)

# CircleCI does not allow mounting certain folders 
# so we could only
# - copy source code to Docker container
# - compile and optimise the Wasm binary
# - copy everything back to the CircleCI machine
# https://circleci.com/docs/building-docker-images/#mounting-folders
build-optimized-ci:
	@$(DOCKER) build -t $(OPTIMIZER_IMAGE_NAME):$(OPTIMIZER_IMAGE_TAG) -f ./Dockerfile-ci .
	@$(DOCKER) run --name rust-optimizer-container \
		--mount type=volume,source="$(CUR_BASENAME)_cache",target=/code/target \
		--mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
		$(OPTIMIZER_IMAGE_NAME):$(OPTIMIZER_IMAGE_TAG)
	@$(DOCKER) cp rust-optimizer-container:/code/artifacts /home/circleci/project/artifacts

.PHONY: build test-ci lint test integration-test schema proto-gen rust-optimizer-image build-optimized build-optimized-ci
