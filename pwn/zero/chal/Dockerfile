FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    qemu-system-x86 \
    socat \
    && apt-get clean

  WORKDIR /app
  COPY ./run.sh /app/run.sh
  COPY ./initramfs.cpio.gz /app/initramfs.cpio.gz
  COPY ./bzImage /app/bzImage

  CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:"/app/run.sh"
