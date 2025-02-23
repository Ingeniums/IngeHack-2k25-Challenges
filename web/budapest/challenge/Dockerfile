FROM golang:1.22-alpine

RUN apk add --no-cache build-base sqlite-dev

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o main main.go

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

CMD [ "./main" ]
