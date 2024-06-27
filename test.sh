#!/usr/bin/env bash

cargo build
mkdir -p logs
sudo target/debug/albion-chat-sniffer > logs/out.log

