#!/bin/sh

EXEC="./server.py"
PORT=1026

socat -dd -T300 tcp-l:$PORT,reuseaddr,fork,keepalive, exec:"python3 $EXEC",stderr