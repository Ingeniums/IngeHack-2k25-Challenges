#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 quiet loglevel=3 pti=on nokaslr" \
    -monitor /dev/null \
    -initrd "./initramfs.cpio.gz" \
    -cpu qemu64,+smep \
    -smp cores=2
