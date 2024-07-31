#!/bin/bash

DOCKER=$(which docker)
CUR_DIR=$(pwd)
CUR_BASENAME=$(basename $CUR_DIR)

# Native arch
BUILDARCH=$(uname -m)
DOCKERFILE=./docker/Dockerfile-$BUILDARCH
OPTIMIZER_IMAGE_NAME="babylonlabs-io/rust-optimizer-$BUILDARCH"
OPTIMIZER_IMAGE_TAG=$(sed -n -E 's/^FROM.*:([^ 	]*)[ 	].*/\1/p' $DOCKERFILE)

$DOCKER build -t $OPTIMIZER_IMAGE_NAME:$OPTIMIZER_IMAGE_TAG -f $DOCKERFILE .
$DOCKER tag $OPTIMIZER_IMAGE_NAME:$OPTIMIZER_IMAGE_TAG $OPTIMIZER_IMAGE_NAME
