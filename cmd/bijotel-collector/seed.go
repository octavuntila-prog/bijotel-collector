// `bijotel-collector seed --db PATH --count N` writes N synthetic gen_ai
// spans into the chain. It exists for the cross-compat gate: we seed a
// chain.db with Go, then run `bijotel verify` (Python) against it. If
// VALID, the Go writer is byte-compatible with the Python one.
//
// Not intended for production use — production traffic comes through
// the OTLP receiver (cmd/bijotel-collector main path).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/octavuntila-prog/bijotel-collector/internal/chain"
)

// seedCmd is wired by main.go when argv[1] == "seed". Kept as a
// top-level helper so production main stays readable.
func seedCmd(args []string) int {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	dbPath := fs.String("db", "chain.db", "chain.db path to seed into")
	count := fs.Int("count", 10, "number of synthetic spans to seal")
	secretHex := fs.String("secret-hex", "", "HMAC secret in hex (default: env BIJOTEL_HMAC_SECRET)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	secret, err := resolveSecret(*secretHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 2
	}

	cw, err := chain.NewChainWriter(*dbPath, secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	defer cw.Close()

	// Deterministic-ish timestamps so re-running with --count N
	// produces a chain that any verifier can replay.
	baseTs := int64(1700000000000000000) // 2023-11-14 UTC
	for i := 0; i < *count; i++ {
		ts := baseTs + int64(i)*int64(time.Second)
		seq, err := cw.Seal(chain.SpanRecord{
			Name: fmt.Sprintf("anthropic.chat.%d", i),
			Kind: "CLIENT",
			Attributes: map[string]interface{}{
				"gen_ai.provider.name":       "anthropic",
				"gen_ai.request.model":       "claude-haiku-4-5",
				"gen_ai.usage.input_tokens":  100 + i,
				"gen_ai.usage.output_tokens": 50 + i,
			},
			StatusCode:  "OK",
			StartTimeNs: ts,
			EndTimeNs:   ts + int64(100*time.Millisecond),
			// Distinct trace/span IDs per row so the schema's NOT NULL
			// holds and the chain looks like a real production stream.
			TraceID: fmt.Sprintf("%032x", i+1),
			SpanID:  fmt.Sprintf("%016x", i+1),
		})
		if err != nil {
			log.Fatalf("seed %d: %v", i, err)
		}
		_ = seq
	}

	fmt.Printf("Seeded %d spans into %s\n", *count, *dbPath)
	return 0
}
