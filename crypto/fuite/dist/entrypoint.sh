#!/bin/sh

EXEC="./leaky.py"
PORT=1024

socat -dd -T300 tcp-l:$PORT,reuseaddr,fork,keepalive, exec:"python3 $EXEC",stderr