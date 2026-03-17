# Build stage
FROM golang:1.23-alpine AS builder

RUN apk --no-cache add git

WORKDIR /src
COPY go.mod ./
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /argus ./cmd/argus/

# Test stage (optional: run tests during build)
FROM builder AS tester
RUN go test ./... -count=1 -timeout 60s

# Runtime stage
FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata && \
    adduser -D -H -s /sbin/nologin argus && \
    mkdir -p /etc/argus /var/log/argus && \
    chown argus:argus /var/log/argus

COPY --from=builder /argus /usr/local/bin/argus

USER argus

EXPOSE 15432 13306 11433 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:9091/livez || exit 1

ENTRYPOINT ["argus"]
CMD ["-config", "/etc/argus/argus.json"]
