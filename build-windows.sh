#!/bin/bash

set -e

# Set the MinGW-w64 cross-compiler
export CC=x86_64-w64-mingw32-gcc
export CGO_ENABLED=1
export GOOS=windows
export GOARCH=amd64

go build -o ransomware.exe .