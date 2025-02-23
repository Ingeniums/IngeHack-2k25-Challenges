FROM python:3-alpine

RUN apk update && \
    apk add socat && pip install pycryptodome

COPY ./dist /dist

WORKDIR /dist

RUN chmod +x entrypoint.sh casino.py 

EXPOSE 1030

ENTRYPOINT ["./entrypoint.sh"]