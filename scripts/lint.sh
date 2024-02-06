#!/bin/bash

cargo fmt --all -- --check
cargo check
cargo clippy --all-targets -- -D warnings
