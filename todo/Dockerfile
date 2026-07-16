FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /todo-server .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /todo-server /usr/local/bin/todo-server

EXPOSE 8080

ENTRYPOINT ["todo-server"]
