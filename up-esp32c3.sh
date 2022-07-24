#!/bin/bash

docker run --name rust-esp32-std-demo_esp32c3 --rm \
	-v $HOME/Repository/Software/Programming/IDF-Rust/registry:/home/esp/.cargo/registry \
	-v $HOME/Workspace/GitHub/rust-esp32-std-demo:/rust-esp32-std-demo \
	-w /rust-esp32-std-demo \
	-it espressif/idf-rust:esp32c3_v4.4_1.62.0.0_classic
