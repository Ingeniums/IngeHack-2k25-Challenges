#!/bin/bash

qemu-system-i386 -L /bios -display none -drive format=raw,file=./bootflop.img -serial stdio
