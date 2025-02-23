#!/bin/sh

EXEC="./chal.py"
PORT=5000

socat -dd -T300 tcp-l:$PORT,reuseaddr,fork,keepalive, exec:"python3 $EXEC",stderr