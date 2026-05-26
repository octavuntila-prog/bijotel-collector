// bijotel-collector — OTLP receiver that seals GenAI spans into a
// BIJOTEL HMAC chain. v0.1.0 ships:
//
//   bijotel-collector serve  — OTLP/gRPC :4317 → chain.db
//   bijotel-collector seed   — write synthetic rows for testing
//   bijotel-collector verify — sanity-check the chain (full verify
//                              stays in the Python `bijotel verify`)
//
// The Python CLI remains the auditor of record (see design doc §4).
// This binary writes; the operator reads with Python BIJOTEL.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(serveCmd(os.Args[2:]))
	case "seed":
		os.Exit(seedCmd(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("bijotel-collector", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "ERROR: unknown subcommand:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `bijotel-collector — OTLP receiver for the BIJOTEL HMAC chain

Usage:
  bijotel-collector serve --db PATH [--port 4317]
  bijotel-collector seed  --db PATH [--count 10]
  bijotel-collector version

Environment:
  BIJOTEL_HMAC_SECRET   HMAC secret (hex). Required for serve/seed.

Verify the chain with the Python CLI:
  pip install bijotel
  bijotel verify --db <PATH>`)
}

// resolveSecret pulls the HMAC secret either from the --secret-hex
// flag (if given) or from BIJOTEL_HMAC_SECRET. Returns raw bytes (hex
// decoded). Minimum length 16 is enforced by the chain writer.
func resolveSecret(flagHex string) ([]byte, error) {
	src := flagHex
	if src == "" {
		src = os.Getenv("BIJOTEL_HMAC_SECRET")
	}
	if src == "" {
		return nil, fmt.Errorf("HMAC secret missing (set --secret-hex or env BIJOTEL_HMAC_SECRET)")
	}
	// If the value parses as hex, decode it. Otherwise treat the
	// string itself as the secret bytes — matches Python BIJOTEL's
	// dual-mode behaviour where the secret can be raw or hex.
	if b, err := hex.DecodeString(src); err == nil {
		return b, nil
	}
	return []byte(src), nil
}
