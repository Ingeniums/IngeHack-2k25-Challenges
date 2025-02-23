FROM pwn.red/jail

ENV JAIL_TIME=120

COPY --from=ubuntu:24.04 / /srv
COPY main /srv/app/run
COPY flag.txt /srv/app/flag.txt
ENV JAIL_TIME=120
