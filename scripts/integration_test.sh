#!/bin/bash

./scripts/optimizer.sh

cargo test --test integration
