FROM golang:1.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o app

FROM debian:latest

RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

COPY --from=builder /app/app .

COPY .env .env

RUN chown appuser:appgroup /app/app /app/.env

USER appuser

EXPOSE 8080

CMD ["./app"]
