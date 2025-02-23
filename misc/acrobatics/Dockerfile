FROM python:3-alpine

RUN apk update && apk add socat

WORKDIR /app

COPY ./challenge/main.py /app/main.py
COPY ./challenge/entrypoint.sh /app/entrypoint.sh
COPY ./challenge/flag.txt /app/flag.txt

RUN chmod +x main.py entrypoint.sh

EXPOSE 1337


CMD ["sh", "/app/entrypoint.sh"]
