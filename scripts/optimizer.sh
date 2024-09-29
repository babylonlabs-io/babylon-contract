#!/bin/bash

DOCKER=$(which docker)
CUR_DIR=$(pwd)
CUR_BASENAME=$(basename $CUR_DIR)

OPTIMIZER_IMAGE_NAME="babylonlabs/optimizer"

$DOCKER run --rm -v "$CUR_DIR":/code \
  --mount type=volume,source="${CUR_BASENAME}_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  $OPTIMIZER_IMAGE_NAME
