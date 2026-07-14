# Admin UI build stage
FROM node:22-alpine AS admin-ui-builder

WORKDIR /src
COPY admin-ui/package.json admin-ui/package-lock.json* ./
RUN npm ci --silent 2>/dev/null || npm install --silent
COPY admin-ui/ .
RUN npx vite build --logLevel error

# Build stage
FROM golang:1.24-alpine AS builder

RUN apk --no-cache add git

WORKDIR /src
COPY go.mod ./
COPY . .

# Copy prebuilt admin UI into the embed directory
COPY --from=admin-ui-builder /src/dist/ ./internal/admin/adminui/

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /argus ./cmd/argus/

# Test stage (optional: run tests during build)
FROM builder AS tester
RUN go test ./... -count=1 -timeout 60s

# Runtime stage
FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata curl && \
    adduser -D -H -s /sbin/nologin argus && \
    mkdir -p /etc/argus/policies /var/log/argus && \
    chown argus:argus /var/log/argus

COPY --from=builder /argus /usr/local/bin/argus
COPY configs/policies/ /etc/argus/policies/
COPY configs/argus-gateway.json /etc/argus/argus-gateway.json

# Default environment variables for proxy gateway
ENV ARGUS_ADMIN_ENABLED=true
ENV ARGUS_ADMIN_AUTH_TOKEN=""
ENV ARGUS_GATEWAY_ENABLED=true

USER argus

EXPOSE 15432 13306 11433 17017 9090 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:9091/livez || exit 1

ENTRYPOINT ["argus"]
CMD ["-config", "/etc/argus/argus.json"]
