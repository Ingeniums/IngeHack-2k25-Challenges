#!/bin/sh

EXEC="./server.py"
PORT=2020

socat -dd -T300 tcp-l:$PORT,reuseaddr,fork,keepalive, exec:"sage -python $EXEC",stderr