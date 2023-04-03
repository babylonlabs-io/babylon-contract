DOCKER := $(shell which docker)
CUR_DIR := $(shell pwd)
CUR_BASENAME := $(shell basename $(CUR_DIR))
OPTIMIZER_IMAGE_NAME := "babylonchain/rust-optimizer"
OPTIMIZER_IMAGE_TAG := "0.0.1"
# Native arch
BUILDARCH := $(shell uname -m)

rust-optimizer-image:
	$(DOCKER) build -t $(OPTIMIZER_IMAGE_NAME)-$(BUILDARCH):$(OPTIMIZER_IMAGE_TAG) -f ./Dockerfile-$(BUILDARCH) .

build-optimized:
	if [ -z $$(docker images -q $(OPTIMIZER_IMAGE_NAME)-$(BUILDARCH)) ]; then \
        make rust-optimizer-image; \
    fi
	$(DOCKER) run --rm -v "$(CUR_DIR)":/code \
		--mount type=volume,source="$(CUR_BASENAME)_cache",target=/code/target \
		--mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
		$(OPTIMIZER_IMAGE_NAME):$(OPTIMIZER_IMAGE_TAG)

proto-gen:
	@echo "Generating Protobuf files"
	@sh ./scripts/protocgen.sh