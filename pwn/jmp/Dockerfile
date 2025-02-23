FROM pwn.red/jail

ENV JAIL_PORT=1337
ENV JAIL_TIME=120

COPY --from=ubuntu / /srv

COPY ./challenge/libcapstone.so.5 /srv/lib/libcapstone.so.5
COPY ./challenge/libc.so.6 /srv/app/libc.so.6
COPY ./challenge/ld.so.2 /srv/app/ld.so.2
COPY ./challenge/out_patched /srv/app/run
COPY ./challenge/flag.txt /srv/app/flag.txt



RUN chmod 755 /srv/app/run

ENV LD_LIBRARY_PATH=/srv/lib