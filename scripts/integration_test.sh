#!/bin/bash

./scripts/optimizer.sh
M=$(uname -m)

if [ "$M" = "arm64" ]
then
  for A in ./artifacts/*-aarch64.wasm
  do
    B=$(basename $A -aarch64.wasm)
    cp "$A" ./artifacts/"$B".wasm
  done
fi

cargo test --test integration
