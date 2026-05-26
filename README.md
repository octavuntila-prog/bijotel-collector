# bijotel-collector

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**OTLP receiver that seals GenAI spans into a tamper-evident BIJOTEL HMAC chain.**

The Go companion to [**BIJOTEL**](https://github.com/octavuntila-prog/BIJOTEL) (Python).
**bijotel-collector writes the chain. Python BIJOTEL verifies it.** Same
schema, same hash formula, same canonical-body bytes — byte-for-byte
cross-compatible.

## Why it exists

BIJOTEL's Python writer requires `pip install bijotel` plus a
`SpanProcessor` hook inside the host application. That's perfect for
greenfield Python code but blocks adoption in two real cases:

1. **Polyglot fleets.** Production AI gateways (Kong AI, Bifrost,
   Portkey, LiteLLM) are written in Go / Rust / TS and already emit
   OpenTelemetry traces.
2. **No-app-change deployments.** Platform teams that don't own the
   application code can't merge a Python `SpanProcessor` patch into
   someone else's service.

`bijotel-collector` sits on the OTLP path: applications point their
existing OTLP exporters at it; it seals every `gen_ai.*` span into a
chain.db that the operator audits with Python BIJOTEL.

```
+--------------+     OTLP/gRPC :4317     +--------------------+
| any LLM app  | ----------------------> | bijotel-collector  |
+--------------+                         +----------+---------+
                                                    |
                                                    v
                                              /data/chain.db
                                                    |
                                                    v
                                +------------------------------------+
                                | $ bijotel verify --db chain.db     |
                                |   ✓ Chain VALID (N entries)        |
                                +------------------------------------+
```

## Quick start

```bash
# 64-hex-char HMAC secret. Same one both sides.
export BIJOTEL_HMAC_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

# Run the collector (OTLP/gRPC on :4317, writes to chain.db)
bijotel-collector serve --db /data/chain.db --port 4317

# Point any OTLP-emitting app at it...
# (your app exports to grpc://localhost:4317)

# Then verify with Python BIJOTEL on any machine:
pip install bijotel
bijotel verify --db /data/chain.db
# → Chain VALID (N entries).
```

## Docker

The published image lives at `ghcr.io/octavuntila-prog/bijotel-collector`
(tags: `:0.1.0`, `:latest`). Default entrypoint is `serve` on `:4317`
with the chain at `/data/chain.db`:

```bash
docker run -p 4317:4317 \
  -e BIJOTEL_HMAC_SECRET=your-64-hex-secret \
  -v bijotel-data:/data \
  ghcr.io/octavuntila-prog/bijotel-collector:latest
```

Or override the default command — e.g. seed a chain for cross-compat
testing:

```bash
docker run --rm \
  -e BIJOTEL_HMAC_SECRET=your-64-hex-secret \
  -v "$PWD":/data \
  ghcr.io/octavuntila-prog/bijotel-collector:latest \
  seed --db /data/chain.db --count 10
```

Image size: ~32 MB (Alpine + statically linked pure-Go binary). No
CGo, no libc dependency at runtime.

## Subcommands

| Command | Purpose |
|---|---|
| `bijotel-collector serve --db PATH [--port 4317] [--host 0.0.0.0]` | OTLP/gRPC receiver; seals every `gen_ai.*` span into the chain |
| `bijotel-collector seed --db PATH [--count N]` | Write N synthetic gen_ai spans (useful for cross-compat sanity checks) |
| `bijotel-collector version` | Print version |

All subcommands honour `BIJOTEL_HMAC_SECRET` (env) or `--secret-hex`
(flag). Both accept either a hex string (decoded) or a raw byte string
(used as-is), matching Python BIJOTEL's dual-mode behaviour.

## What it captures

For every OTLP span where any attribute key starts with `gen_ai.`:

- `span.name`, `span.kind`, `span.status_code`, `span.status_description`
- `trace_id`, `span_id` (hex)
- `start_time_unix_nano`, `end_time_unix_nano` (stringified for JCS)
- all string / int / float / bool attributes (nested arrays / kvlists skipped in v0.1.0)

The canonical body shape matches Python BIJOTEL's
`span_to_canonical_dict` exactly. The HMAC chain links each row to the
previous using `HMAC-SHA256(secret, prev_hash + canonical_hash)`.

## Cross-compatibility guarantee

The single critical promise:

> Any chain.db written by `bijotel-collector` MUST verify VALID under
> Python `bijotel verify --db <path>`.

CI runs this gate on every PR: seed 10 rows from Go, run Python
`bijotel verify`, fail the build on anything but `Chain VALID`. If the
gate ever goes red, it's a release blocker.

Verified shapes (v0.1.0):

- ✓ Basic GenAI spans (string + integer attributes)
- ✓ Multi-row chains, resume across writer restarts
- ✓ HMAC link integrity (re-open writer picks up `prev_hash` from last row)

Known limits, tracked in design doc §9:

- Unicode normalisation (NFC) not performed — ASCII inputs unaffected
- Float values not canonicalised to ECMA-262 minimum-form — stringify floats you need verbatim
- Nested arrays / KV-list attribute values are dropped (string/int/float/bool only)

## Build from source

```bash
git clone https://github.com/octavuntila-prog/bijotel-collector.git
cd bijotel-collector
make build         # → ./bijotel-collector
make test          # unit tests
make docker        # docker image
```

Or directly with Docker (no local Go install needed):

```bash
docker run --rm -v "$PWD":/work -w /work golang:1.22-alpine \
  sh -c 'go build -o bin/bijotel-collector ./cmd/bijotel-collector'
```

## Architecture

Full architecture spec lives in BIJOTEL's design doc:
[**OTel Collector Exporter — Design**](https://github.com/octavuntila-prog/BIJOTEL/blob/main/docs/design/otel-collector-exporter.md).

TL;DR:

- **Pure-Go SQLite** (`modernc.org/sqlite`). No CGo. Static binaries
  on every platform Go cross-compiles to.
- **Standalone OTLP receiver** in v0.1.0. Full OTel Collector plugin
  mode is on the v0.3.0 roadmap.
- **Trust split.** This binary writes. It never verifies. Verification
  stays in Python BIJOTEL — fewer than 200 LOC of audit code that
  anyone can read in one sitting.

## License

[MIT](LICENSE) — same as Python BIJOTEL.
