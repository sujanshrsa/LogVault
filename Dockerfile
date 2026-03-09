# ─────────────────────────────────────────────
# Stage 1: Build — golang:alpine (build only)
# ─────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Copy source and build a fully static binary (CGO disabled)
COPY app/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o logvault .

# ─────────────────────────────────────────────
# Stage 2: Runtime — scratch (zero OS overhead)
# ─────────────────────────────────────────────
FROM scratch

# Copy CA certificates from builder so HTTPS works if needed
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary
COPY --from=builder /build/logvault /logvault

# The logs directory will be mounted here at runtime
VOLUME ["/app/logs"]

EXPOSE 8080

ENTRYPOINT ["/logvault"]
