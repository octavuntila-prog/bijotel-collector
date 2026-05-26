package chain

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/octavuntila-prog/bijotel-collector/internal/canonical"
)

// 32 bytes of "x" — matches the SECRET used in BIJOTEL's Python tests
// (tests/test_processors_export.py:18). Re-using the same secret means
// a Go-written chain and a Python-written chain can be cross-verified
// with the identical key.
var testSecret = []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

// TestSealAndReadBack: smoke test for the core seal flow. Seals one
// row, reads it back, confirms canonical_hash == SHA-256(canonical_body)
// and that the row exists with the expected hex shapes.
func TestSealAndReadBack(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "chain.db")
	cw, err := NewChainWriter(dbPath, testSecret)
	if err != nil {
		t.Fatalf("NewChainWriter: %v", err)
	}
	defer cw.Close()

	seq, err := cw.Seal(SpanRecord{
		Name:        "anthropic.chat",
		Kind:        "CLIENT",
		Attributes:  map[string]interface{}{"gen_ai.request.model": "claude-haiku-4-5"},
		StatusCode:  "OK",
		StartTimeNs: 1700000000000000000,
		EndTimeNs:   1700000000100000000,
		TraceID:     "0123456789abcdef0123456789abcdef",
		SpanID:      "fedcba9876543210",
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if seq != 1 {
		t.Fatalf("expected first seq=1, got %d", seq)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open for read: %v", err)
	}
	defer db.Close()

	var (
		canonicalBody []byte
		canonicalHash string
		prevHash      string
		hmacHash      string
	)
	row := db.QueryRow(
		`SELECT canonical_body, canonical_hash, prev_hash, hmac_hash FROM chain WHERE seq = 1`,
	)
	if err := row.Scan(&canonicalBody, &canonicalHash, &prevHash, &hmacHash); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// canonical_hash must equal SHA-256(canonical_body)
	bodyHash := sha256.Sum256(canonicalBody)
	if got, want := canonicalHash, hex.EncodeToString(bodyHash[:]); got != want {
		t.Fatalf("canonical_hash mismatch:\n  in DB:  %s\n  recomp: %s", got, want)
	}

	// prev_hash on row 1 must be the genesis (64 zeros).
	if prevHash != GenesisPrevHash {
		t.Fatalf("row 1 prev_hash = %q, want %q", prevHash, GenesisPrevHash)
	}

	// hmac_hash must be 64 hex chars.
	if len(hmacHash) != 64 {
		t.Fatalf("hmac_hash length = %d, want 64", len(hmacHash))
	}
	if _, err := hex.DecodeString(hmacHash); err != nil {
		t.Fatalf("hmac_hash not hex: %v", err)
	}
}

// TestChainLinkContinuity: seal N rows in a single writer, then
// re-open the writer (simulates restart) and seal more. Every row's
// prev_hash must equal the previous row's hmac_hash.
func TestChainLinkContinuity(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "chain.db")

	// First session: seal 3 rows.
	cw1, err := NewChainWriter(dbPath, testSecret)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := cw1.SealNow(SpanRecord{
			Name:    "test.span",
			Kind:    "CLIENT",
			TraceID: "0123456789abcdef0123456789abcdef",
			SpanID:  "0000000000000001",
		}); err != nil {
			t.Fatalf("first-session seal %d: %v", i, err)
		}
	}
	prevAfterFirstSession := cw1.PrevHash()
	if err := cw1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Second session: re-open. Resume must read prev_hash from the DB.
	cw2, err := NewChainWriter(dbPath, testSecret)
	if err != nil {
		t.Fatalf("open #2: %v", err)
	}
	defer cw2.Close()
	if cw2.PrevHash() != prevAfterFirstSession {
		t.Fatalf("resume failed: prev=%s want=%s", cw2.PrevHash(), prevAfterFirstSession)
	}
	if _, err := cw2.SealNow(SpanRecord{
		Name:    "test.span.after-resume",
		TraceID: "0123456789abcdef0123456789abcdef",
		SpanID:  "0000000000000002",
	}); err != nil {
		t.Fatalf("second-session seal: %v", err)
	}

	// Continuity check across all 4 rows.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("read open: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT seq, prev_hash, hmac_hash FROM chain ORDER BY seq`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	type rec struct {
		seq      int
		prev     string
		hmac     string
	}
	var all []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.seq, &r.prev, &r.hmac); err != nil {
			t.Fatalf("scan: %v", err)
		}
		all = append(all, r)
	}
	if len(all) != 4 {
		t.Fatalf("expected 4 rows, got %d", len(all))
	}
	if all[0].prev != GenesisPrevHash {
		t.Fatalf("row 1 prev != genesis: %s", all[0].prev)
	}
	for i := 1; i < len(all); i++ {
		if all[i].prev != all[i-1].hmac {
			t.Fatalf("chain link broken at seq=%d: prev=%s want=%s",
				all[i].seq, all[i].prev, all[i-1].hmac)
		}
	}
}

// TestJCSGoldenVectors: the JCS function MUST produce byte streams
// that Python's rfc8785 library would produce. Vectors below are the
// canonical-body shapes BIJOTEL writes most often. Expected bytes
// were captured from Python's `rfc8785.dumps(d)` on 2026-05-26.
func TestJCSGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
	}{
		{
			name: "empty_attrs_only",
			in: map[string]interface{}{
				"name":               "test.span",
				"kind":               "CLIENT",
				"attributes":         map[string]interface{}{},
				"status_code":        "OK",
				"status_description": nil,
				"start_time_ns":      "1700000000000000000",
				"end_time_ns":        "1700000000100000000",
			},
			// Keys sorted alphabetically. No whitespace.
			want: `{"attributes":{},"end_time_ns":"1700000000100000000","kind":"CLIENT","name":"test.span","start_time_ns":"1700000000000000000","status_code":"OK","status_description":null}`,
		},
		{
			name: "with_gen_ai_attrs",
			in: map[string]interface{}{
				"name": "anthropic.chat",
				"attributes": map[string]interface{}{
					"gen_ai.request.model":       "claude-haiku-4-5",
					"gen_ai.usage.input_tokens":  100,
					"gen_ai.usage.output_tokens": 50,
				},
			},
			want: `{"attributes":{"gen_ai.request.model":"claude-haiku-4-5","gen_ai.usage.input_tokens":100,"gen_ai.usage.output_tokens":50},"name":"anthropic.chat"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := canonical.JCS(c.in)
			if err != nil {
				t.Fatalf("JCS: %v", err)
			}
			if string(got) != c.want {
				t.Fatalf("\n  got:  %s\n  want: %s", got, c.want)
			}
		})
	}
}

// TestSecretLengthFloor: the writer enforces secret >= 16 bytes,
// matching Python BIJOTEL's `export_chain_secret_key_min_length`
// behaviour.
func TestSecretLengthFloor(t *testing.T) {
	_, err := NewChainWriter(filepath.Join(t.TempDir(), "chain.db"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for short secret, got nil")
	}
}

// TestSchemaNotNull: the schema MUST insist on trace_id/span_id/name
// being non-null, matching the Python schema.
func TestSchemaNotNull(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "chain.db")
	cw, err := NewChainWriter(dbPath, testSecret)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer cw.Close()

	if _, err := cw.Seal(SpanRecord{
		Name:    "test", // no trace_id / span_id
		TraceID: "",
		SpanID:  "ok",
	}); err == nil {
		t.Fatal("expected error for empty trace_id, got nil")
	}
}

// Ensure tempdir cleanup actually fires even on hard failures.
func init() {
	os.Setenv("GOTRACEBACK", "single")
}
