#!/bin/sh
# Indirection in case you want to set up LD_LIBRARY_PATH etc...
. ./build-paths.sh
cargo build --release
