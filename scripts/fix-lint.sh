#!/bin/bash

cargo fmt --all
cargo clippy --all-targets --fix --allow-dirty --allow-staged
