FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    wget \
    tar \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget -O go.tar.gz https://go.dev/dl/go1.22.3.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV GOBIN="/go/bin"

RUN go version

WORKDIR /app

COPY ./build/main main

RUN chmod +x main

EXPOSE 8080

CMD [ "./main" ]


# docker build -t redacted .
# docker run -p 8080:8080 redacted