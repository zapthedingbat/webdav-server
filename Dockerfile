# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download && go mod tidy && CGO_ENABLED=0 go build -o /webdav-server ./cmd/server

# Runtime stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /webdav-server .
COPY config.default.yaml /app/config.default.yaml
COPY index.default.html /app/index.default.html
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
VOLUME /config
EXPOSE 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/app/webdav-server"]
