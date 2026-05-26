# Multi-stage build for bijotel-collector.
#
# Stage 1: compile a static binary against Go 1.22 + modernc.org/sqlite
#   (pure Go — no CGo, no libc dependency at runtime).
#
# Stage 2: minimal alpine image with the binary copied across. Final
#   image is ~25 MB (binary ~19 MB + alpine base).
#
# Usage:
#   docker build -t bijotel-collector .
#   docker run -p 4317:4317 \
#     -e BIJOTEL_HMAC_SECRET=<64-hex> \
#     -v bijotel-data:/data \
#     bijotel-collector serve --db /data/chain.db

# ───────────────────────── builder ─────────────────────────

FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git
WORKDIR /src

# Dep layer cached separately so source-only changes don't re-download.
COPY go.mod go.sum ./
RUN go mod download

# Source.
COPY . .

# CGO disabled — modernc.org/sqlite is pure Go.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/bijotel-collector \
    ./cmd/bijotel-collector

# ───────────────────────── runtime ─────────────────────────

FROM alpine:3.20

# ca-certificates so the binary can reach external services if/when we
# add outbound HTTPS (e.g. push-mode export to a central audit store).
# Nothing else needed — the chain writer talks to SQLite + listens on
# gRPC, no DNS surprises.
RUN apk add --no-cache ca-certificates \
    && addgroup -g 1000 bijotel \
    && adduser -D -u 1000 -G bijotel bijotel \
    && mkdir -p /data \
    && chown -R bijotel:bijotel /data

COPY --from=builder /out/bijotel-collector /usr/local/bin/

USER bijotel
WORKDIR /home/bijotel

EXPOSE 4317

ENTRYPOINT ["bijotel-collector"]
CMD ["serve", "--db", "/data/chain.db", "--host", "0.0.0.0", "--port", "4317"]
