DOCKER := $(shell which docker)
CUR_DIR := $(shell pwd)
CUR_BASENAME := $(shell basename $(CUR_DIR))

build-optimized:
	$(DOCKER) run --rm -v "$(CUR_DIR)":/code \
		--mount type=volume,source="$(CUR_BASENAME)_cache",target=/code/target \
		--mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
		cosmwasm/rust-optimizer:0.12.12

proto-gen:
	@echo "Generating Protobuf files"
	@sh ./scripts/protocgen.sh