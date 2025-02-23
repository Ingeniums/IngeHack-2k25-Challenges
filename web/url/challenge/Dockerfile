FROM golang:1.23-alpine AS builder

RUN apk add --no-cache bash

WORKDIR /app

COPY src/go.mod ./

RUN go mod download

COPY src/* ./

RUN set -o allexport && \
    source .env && \
    mkdir -p /app/freepalestine && \
    mv /app/flag.txt /app/freepalestine/$SECRET_FILE

RUN go build -o main .

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

CMD ["./main"]
