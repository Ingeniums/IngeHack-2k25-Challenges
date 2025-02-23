#!/bin/sh

EXEC="./casino.py"
PORT=1030

socat -dd -T300 tcp-l:$PORT,reuseaddr,fork,keepalive, exec:"python3 -W ignore $EXEC",stderr
