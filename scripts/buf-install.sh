#!/bin/bash

BIN="/usr/local/bin"
VERSION="1.25.0"

curl -sSL "https://github.com/bufbuild/buf/releases/download/v${VERSION}/buf-$(uname -s)-$(uname -m)" -o "${BIN}/buf"
chmod +x "${BIN}/buf"
