FROM golang:1.27-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dumpd .

FROM alpine:3.24
RUN apk add --no-cache mailcap \
    && adduser -D -u 10001 dumpd \
    && mkdir -p /data \
    && chown dumpd:dumpd /data
COPY --from=build /dumpd /usr/local/bin/dumpd
USER dumpd
ENV DATA_DIR=/data
VOLUME /data
# Binding :80/:443 as uid 10001 relies on
#   sysctl net.ipv4.ip_unprivileged_port_start=0
# which both compose files set. A bare `docker run` needs
#   --sysctl net.ipv4.ip_unprivileged_port_start=0
# (file capabilities were dropped: they conflict with
#  security_opt no-new-privileges and cap_drop ALL anyway.)
EXPOSE 8080 80 443
# /healthz is plain HTTP on ADDR (http fallback or plain mode); the TLS port
# can't be probed with busybox wget, so fall back to a TCP connect check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD sh -c 'for a in "${ADDR:-}" ":8080"; do p="${a##*:}"; case "$p" in ""|*[!0-9]*) continue;; esac; wget -q -T 3 -O /dev/null "http://127.0.0.1:$p/healthz" 2>/dev/null && exit 0; done; p="${TLS_ADDR:-:443}"; p="${p##*:}"; case "$p" in ""|*[!0-9]*) exit 1;; esac; nc -w 2 127.0.0.1 "$p" </dev/null >/dev/null 2>&1'
ENTRYPOINT ["dumpd"]
