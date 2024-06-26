#!/usr/bin/env bash

cargo build; sudo target/debug/albion-chat-sniffer | stdbuf -oL grep 1234567890 > logs/say.log

