#!/usr/bin/env bash

# This script generates protobuf messages in Rust for the Wasm smart contract
# NOTE: use `cargo run-script gen-proto` in the root dir instead.

set -eo pipefail

cd packages/proto
# To also initialize, fetch and checkout any nested submodules
git submodule update --init --recursive
# Checkout the consumer-chain-support branch
cd babylon
git checkout base/consumer-chain-support
cd ..
# Update the buf.yaml file to include the consumer-chain-support branch
buf mod update
# Generate the Rust protobuf messages
buf generate --template buf.gen.rust.yaml
cd ../..
