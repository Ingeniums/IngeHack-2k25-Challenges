FROM ubuntu:24.04 as chroot
FROM gcr.io/kctf-docker/challenge:latest

COPY --from=chroot / /chroot
RUN mkdir -p /chroot/home/user
COPY ./chal /chroot/home/user
COPY ./flag.txt /chroot/home/user

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/chal"
