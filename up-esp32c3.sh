#!/bin/bash

docker run --name esp32c3-compiler --rm -v $HOME/Workspace/GitHub/rust-esp32-std-demo:/rust-esp32-std-demo -w /rust-esp32-std-demo -it espressif/idf-rust:esp32c3_v4.4_1.62.0.0

