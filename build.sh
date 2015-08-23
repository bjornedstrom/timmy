#!/bin/sh
# Indirection in case you want to set up LD_LIBRARY_PATH etc...
export PATH=/home/bjorn/Downloads/rust-1.2.0-x86_64-unknown-linux-gnu/cargo/bin:/home/bjorn/Downloads/rust-1.2.0-x86_64-unknown-linux-gnu/rustc/bin:$PATH
export LD_LIBRARY_PATH=/home/bjorn/Downloads/rust-1.2.0-x86_64-unknown-linux-gnu/cargo/lib:/home/bjorn/Downloads/rust-1.2.0-x86_64-unknown-linux-gnu/rustc/lib
cargo build --release
