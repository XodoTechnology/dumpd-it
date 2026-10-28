FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dumpd .

FROM alpine:3.20
RUN apk add --no-cache mailcap libcap \
    && adduser -D -u 10001 dumpd \
    && mkdir -p /data \
    && chown dumpd:dumpd /data
COPY --from=build /dumpd /usr/local/bin/dumpd
# lets the non-root user bind :80/:443 (needed for built-in TLS/ACME)
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/dumpd
USER dumpd
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8080 80 443
HEALTHCHECK --interval=30s --timeout=3s \
    CMD sh -c 'for p in ${ADDR#:} 8080 80; do wget -qO- "http://127.0.0.1:$p/healthz" >/dev/null 2>&1 && exit 0; done; exit 1'
ENTRYPOINT ["dumpd"]
