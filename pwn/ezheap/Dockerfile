FROM pwn.red/jail

ENV JAIL_PORT=1337
ENV JAIL_TIME=120

COPY --from=ubuntu / /srv
COPY ./challenge/out /srv/app/run

COPY ./challenge/flag.txt /srv/app/flag.txt

RUN chmod 755 /srv/app/run