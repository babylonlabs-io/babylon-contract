#!/usr/bin/env bash

# NOTE: use `make proto-gen` in the root dir instead
# This script generates protobuf messages in Rust for the Wasm smart contract

set -eo pipefail

cd packages/proto
buf mod update
buf generate --template buf.gen.rust.yaml
cd ../..
