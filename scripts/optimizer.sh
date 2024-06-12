#!/bin/bash

DOCKER=$(which docker)
CUR_DIR=$(pwd)
CUR_BASENAME=$(basename $CUR_DIR)

# Native arch
BUILDARCH=$(uname -m)
OPTIMIZER_IMAGE_NAME="babylonchain/rust-optimizer-$BUILDARCH"

if [ -z "$($DOCKER images -q $OPTIMIZER_IMAGE_NAME)" ]
then 
  ./scripts/build-optimizer.sh
fi

$DOCKER run --rm -v "$CUR_DIR":/code \
  --mount type=volume,source="${CUR_BASENAME}_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  $OPTIMIZER_IMAGE_NAME
