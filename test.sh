#!/usr/bin/env bash

cargo build
mkdir -p logs
sudo target/debug/albion-chat-sniffer | stdbuf -oL grep 1234567890 > logs/out.log

