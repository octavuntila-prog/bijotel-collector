// Package canonical provides JCS (RFC 8785) canonicalization for the
// bijotel chain. It matches Python's rfc8785 library output for the
// subset of inputs that BIJOTEL chains carry: dicts of strings, ints,
// nested dicts of the same shape, and stringified timestamps.
//
// The implementation leans on Go's encoding/json (which sorts map keys
// lexicographically by default) plus three deliberate overrides:
//
//  1. SetEscapeHTML(false) — Python's rfc8785 does not HTML-escape
//     `<`, `>`, `&`. Go's default encoder does. Turning it off makes
//     the byte streams match.
//  2. No newline at the end. encoding/json's Encoder.Encode appends
//     `\n`; we strip it.
//  3. Integer-only number handling. The canonical body for BIJOTEL
//     deliberately stringifies large integers (timestamp_ns) to dodge
//     the ECMA-262 safe-integer ceiling; everything else is a small
//     int (token counts) or a string. We do not emit floats from this
//     package — callers must convert.
//
// Limits acknowledged for v0.1.0 of bijotel-collector:
//   - Unicode normalization (NFC) is not performed. ASCII inputs
//     (the realistic case for gen_ai attributes) are unaffected.
//   - Float values are not canonicalized to ECMA-262 minimum-form.
//     Callers should stringify floats they need verbatim.
//
// Both limits are tracked in the design doc §9.
package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// JCS serialises v into RFC 8785 canonical JSON bytes that match the
// Python rfc8785 library for the BIJOTEL canonical-body shape.
//
// For maps, keys are sorted alphabetically (Go's encoding/json default).
// HTML-escaping is disabled. The trailing newline that
// json.Encoder.Encode appends is stripped.
func JCS(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("jcs: marshal failed: %w", err)
	}
	// Strip the trailing newline that Encoder.Encode always appends.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}
