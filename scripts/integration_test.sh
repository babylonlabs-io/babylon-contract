#!/bin/bash

./scripts/optimizer.sh
M=$(uname -m)

[ "$M" = "arm64" ] && mv ./artifacts/babylon_contract-aarch64.wasm ./artifacts/babylon_contract.wasm

cargo test --test integration
