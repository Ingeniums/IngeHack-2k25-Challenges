FROM python:3-alpine

RUN apk update && \
    apk add socat 

COPY . /dist

WORKDIR /dist

RUN chmod +x entrypoint.sh chal.py 

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]