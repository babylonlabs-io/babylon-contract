#!/bin/bash

DOCKER=$(which docker)
CUR_DIR=$(pwd)
CUR_BASENAME=$(basename $CUR_DIR)

# Native arch
BUILDARCH=$(uname -m)
DOCKERFILE=./docker/Dockerfile-ci
OPTIMIZER_IMAGE_NAME="babylonchain/rust-optimizer-$BUILDARCH"
OPTIMIZER_IMAGE_TAG=$(sed -n -E 's/^FROM.*:([^\s]*)\s.*/\1/p' $DOCKERFILE)

$DOCKER build -t $OPTIMIZER_IMAGE_NAME:$OPTIMIZER_IMAGE_TAG -f $DOCKERFILE .

$DOCKER run --name rust-optimizer-container \
  --mount type=volume,source="${CUR_BASENAME}_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  $OPTIMIZER_IMAGE_NAME:$OPTIMIZER_IMAGE_TAG

$DOCKER cp rust-optimizer-container:/code/artifacts /home/circleci/project/artifacts
