
#!/bin/sh

EXEC="./main.py"
PORT=1337

socat -dd -T300 tcp-l:$PORT,reuseaddr,fork,keepalive, exec:"python3 $EXEC",stderr