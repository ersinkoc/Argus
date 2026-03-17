# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY . .

ARG VERSION=dev
RUN go build -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /argus ./cmd/argus/

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && \
    adduser -D -H -s /sbin/nologin argus

COPY --from=builder /argus /usr/local/bin/argus

USER argus

EXPOSE 15432 13306 11433 9091

ENTRYPOINT ["argus"]
CMD ["-config", "/etc/argus/argus.json"]
