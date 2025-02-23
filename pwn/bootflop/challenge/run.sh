#!/bin/bash
OUT="$(mktemp /tmp/output.XXXXXXXXXX)"
cp /app/bootflop.img "$OUT"

qemu-system-i386 -L /bios -display none -drive format=raw,file="$OUT" -serial stdio

rm "$OUT"
