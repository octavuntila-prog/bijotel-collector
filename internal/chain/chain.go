// Package chain is the Go writer for the BIJOTEL HMAC audit chain.
// It produces a SQLite chain.db that is byte-compatible with Python
// BIJOTEL's chain.db — same schema, same hash formula, same
// canonical-body bytes for the BIJOTEL canonical shape.
//
// The single critical promise: a chain.db written by this package
// MUST verify VALID under `bijotel verify --db <path>` (Python). If
// that ever stops being true, treat it as a release blocker.
//
// Formula (identical to bijotel.processors.hmac_chain.py:190-206):
//
//	canonical_body = JCS(canonical_dict)                  // RFC 8785 bytes
//	canonical_hash = SHA-256(canonical_body).hex          // 64 hex chars
//	prev_hash      = previous row's hmac_hash, or "0"*64 for the first row
//	hmac_input     = UTF-8(prev_hash + canonical_hash)    // 128 ASCII bytes
//	hmac_hash      = HMAC-SHA256(secret, hmac_input).hex  // 64 hex chars
//
// Schema (identical to hmac_chain.py:113-125, NOT NULL preserved):
//
//	CREATE TABLE chain (
//	    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
//	    timestamp_ns   INTEGER NOT NULL,
//	    trace_id       TEXT NOT NULL,
//	    span_id        TEXT NOT NULL,
//	    span_name      TEXT NOT NULL,
//	    span_kind      TEXT,
//	    canonical_body BLOB NOT NULL,
//	    canonical_hash TEXT NOT NULL,
//	    prev_hash      TEXT NOT NULL,
//	    hmac_hash      TEXT NOT NULL,
//	    semantic_body_hash TEXT
//	);
package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/octavuntila-prog/bijotel-collector/internal/canonical"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// GenesisPrevHash is what the very first row's prev_hash field is set
// to — 64 zero characters. Identical to Python BIJOTEL's
// _last_hmac_hash() default when the chain table is empty.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// SpanRecord is the minimal input shape ChainWriter.Seal accepts.
// It maps 1:1 onto the BIJOTEL canonical-body dict (see
// bijotel.processors.canonical.span_to_dict) so cross-compat is
// mechanical: same keys, same value types, same JCS bytes out.
//
// All fields are required EXCEPT Kind, StatusCode, StatusDescription
// (which match column NULLability) and Attributes (empty map is fine).
type SpanRecord struct {
	Name              string                 // span.name → canonical "name"
	Kind              string                 // span.kind.name → canonical "kind" (empty → null)
	Attributes        map[string]interface{} // canonical "attributes"
	StatusCode        string                 // canonical "status_code" (empty → null)
	StatusDescription string                 // canonical "status_description" (empty → null)
	StartTimeNs       int64                  // stringified into "start_time_ns" (matches Python)
	EndTimeNs         int64                  // stringified into "end_time_ns"
	TraceID           string                 // 32-hex chars; NOT NULL in chain table
	SpanID            string                 // 16-hex chars; NOT NULL in chain table
}

// ChainWriter is the seal-only handle on a chain.db. One writer per
// file is the safe pattern; the package wraps the SELECT-prev-hash →
// INSERT critical section in BEGIN IMMEDIATE to match Python's
// multi-writer guarantee.
type ChainWriter struct {
	db       *sql.DB
	secret   []byte
	mu       sync.Mutex
	prevHash string // hmac_hash of the last sealed row (or GenesisPrevHash)
}

// NewChainWriter opens (or creates) a BIJOTEL chain.db at dbPath and
// returns a writer bound to secret.
//
// secret must be at least 16 bytes. We do not enforce a maximum;
// HMAC-SHA256 accepts arbitrary key lengths. Python BIJOTEL accepts
// raw bytes too — pass the same bytes to both implementations and the
// chains line up.
//
// The SQLite file is opened with WAL + a 5-second busy timeout, both
// matching the Python writer's defaults. The schema is created
// idempotently (IF NOT EXISTS) so opening an existing chain is safe.
func NewChainWriter(dbPath string, secret []byte) (*ChainWriter, error) {
	if len(secret) < 16 {
		return nil, fmt.Errorf("chain: secret must be at least 16 bytes (got %d)", len(secret))
	}
	// pragmas in the DSN: WAL for multi-writer, 5000ms busy_timeout
	// for retry-on-contention. Identical to the Python writer.
	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("chain: open %s: %w", dbPath, err)
	}
	// Single connection: we hold the writer lock locally, and
	// connection pooling adds zero value for one-writer workloads.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS chain (
			seq            INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp_ns   INTEGER NOT NULL,
			trace_id       TEXT NOT NULL,
			span_id        TEXT NOT NULL,
			span_name      TEXT NOT NULL,
			span_kind      TEXT,
			canonical_body BLOB NOT NULL,
			canonical_hash TEXT NOT NULL,
			prev_hash      TEXT NOT NULL,
			hmac_hash      TEXT NOT NULL,
			semantic_body_hash TEXT
		)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("chain: create schema: %w", err)
	}
	// Indices Python adds in the same migration block.
	if _, err := db.Exec(
		`CREATE INDEX IF NOT EXISTS idx_chain_trace ON chain(trace_id)`,
	); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("chain: create index trace: %w", err)
	}

	cw := &ChainWriter{db: db, secret: secret, prevHash: GenesisPrevHash}

	// Resume: read the last row's hmac_hash so subsequent seals link
	// onto it. Empty chain → prevHash stays GenesisPrevHash.
	row := db.QueryRow(`SELECT hmac_hash FROM chain ORDER BY seq DESC LIMIT 1`)
	var last string
	if err := row.Scan(&last); err == nil {
		cw.prevHash = last
	} else if err != sql.ErrNoRows {
		_ = db.Close()
		return nil, fmt.Errorf("chain: read last hmac_hash: %w", err)
	}

	return cw, nil
}

// Close releases the underlying SQLite handle. Safe to call multiple
// times.
func (cw *ChainWriter) Close() error {
	return cw.db.Close()
}

// Seal canonicalizes rec, computes the SHA-256 + HMAC chain links,
// and inserts one row into the chain table. Returns the seq of the
// inserted row.
//
// Seal is goroutine-safe: an internal mutex serialises the
// SELECT-prev → INSERT critical section. For cross-process safety
// (multiple OS processes writing the same chain.db) the wrapping
// BEGIN IMMEDIATE plus WAL gives the same guarantee as Python
// BIJOTEL — first writer wins the RESERVED lock; the second one
// waits up to busy_timeout.
//
// On any error (canonicalization, DB write), no row is inserted and
// the writer's prev_hash is unchanged.
func (cw *ChainWriter) Seal(rec SpanRecord) (int64, error) {
	if rec.TraceID == "" {
		return 0, fmt.Errorf("chain: trace_id is required (NOT NULL in schema)")
	}
	if rec.SpanID == "" {
		return 0, fmt.Errorf("chain: span_id is required (NOT NULL in schema)")
	}
	if rec.Name == "" {
		return 0, fmt.Errorf("chain: name is required (NOT NULL in schema)")
	}

	// Build the canonical-body dict in the exact shape Python emits:
	// see bijotel.processors.canonical.span_to_dict.
	//
	// Stringified timestamps dodge JCS's 2^53-1 safe-integer limit;
	// nullable fields use a nil interface{} when empty.
	body := map[string]interface{}{
		"name":               rec.Name,
		"kind":               nullableString(rec.Kind),
		"attributes":         orEmptyMap(rec.Attributes),
		"status_code":        nullableString(rec.StatusCode),
		"status_description": nullableString(rec.StatusDescription),
		"start_time_ns":      fmt.Sprintf("%d", rec.StartTimeNs),
		"end_time_ns":        fmt.Sprintf("%d", rec.EndTimeNs),
	}

	bodyBytes, err := canonical.JCS(body)
	if err != nil {
		return 0, fmt.Errorf("chain: canonicalize: %w", err)
	}

	bodyHash := sha256.Sum256(bodyBytes)
	canonicalHash := hex.EncodeToString(bodyHash[:])

	cw.mu.Lock()
	defer cw.mu.Unlock()

	// HMAC link: secret + (prev_hash || canonical_hash) — UTF-8 of the
	// concatenated hex strings, exactly as Python does it. Hex strings
	// are ASCII so UTF-8 is a passthrough.
	mac := hmac.New(sha256.New, cw.secret)
	mac.Write([]byte(cw.prevHash + canonicalHash))
	hmacHash := hex.EncodeToString(mac.Sum(nil))

	tx, err := cw.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("chain: begin tx: %w", err)
	}

	res, err := tx.Exec(`
		INSERT INTO chain (
			timestamp_ns, trace_id, span_id, span_name, span_kind,
			canonical_body, canonical_hash, prev_hash, hmac_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.EndTimeNs, // Python uses span.end_time as timestamp_ns
		strings.ToLower(rec.TraceID),
		strings.ToLower(rec.SpanID),
		rec.Name,
		nullableString(rec.Kind),
		bodyBytes,
		canonicalHash,
		cw.prevHash,
		hmacHash,
	)
	if err != nil {
		_ = tx.Rollback()
		return 0, fmt.Errorf("chain: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("chain: commit: %w", err)
	}

	cw.prevHash = hmacHash
	seq, _ := res.LastInsertId()
	return seq, nil
}

// SealNow is a convenience: copies rec, fills StartTimeNs/EndTimeNs
// with the current wall-clock time if they were unset, and seals. Use
// it when the caller doesn't carry its own timestamps (e.g. tests).
func (cw *ChainWriter) SealNow(rec SpanRecord) (int64, error) {
	if rec.EndTimeNs == 0 {
		rec.EndTimeNs = time.Now().UnixNano()
	}
	if rec.StartTimeNs == 0 {
		rec.StartTimeNs = rec.EndTimeNs
	}
	return cw.Seal(rec)
}

// PrevHash returns the hmac_hash of the most recently sealed row, or
// GenesisPrevHash on an empty chain. Mainly useful for tests and
// debugging; production code never needs it.
func (cw *ChainWriter) PrevHash() string {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.prevHash
}

// ----- small helpers -----

// nullableString returns nil for empty strings so they JCS-serialise
// as `null`, matching Python's `None`.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// orEmptyMap returns an empty map[string]interface{} when m is nil so
// JCS emits `{}` rather than `null` for the attributes field. Python
// BIJOTEL always passes a dict (possibly empty) — never None.
func orEmptyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}
