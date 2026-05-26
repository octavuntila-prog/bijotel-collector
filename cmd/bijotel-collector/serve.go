// `bijotel-collector serve` — OTLP/gRPC receiver that seals each
// gen_ai.* span it receives into the chain. See design doc §2-3.
//
// v0.1.0 lifecycle:
//  1. Listen on --port (default 4317).
//  2. Accept ExportTraceServiceRequest.
//  3. For each span where any attribute key starts with "gen_ai.",
//     seal into chain.db.
//  4. Always return OK (the OTel batch contract is "best-effort
//     server-side"). Internal seal failures log but don't fail the
//     gRPC request — same crash-isolation discipline as Python.
//
// Shutdown is graceful on SIGINT/SIGTERM.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"
	collectorv1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/octavuntila-prog/bijotel-collector/internal/chain"
)

func serveCmd(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dbPath := fs.String("db", "chain.db", "chain.db path")
	port := fs.Int("port", 4317, "OTLP/gRPC port")
	host := fs.String("host", "0.0.0.0", "bind address")
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

	addr := fmt.Sprintf("%s:%d", *host, *port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: listen:", err)
		return 3
	}

	srv := grpc.NewServer()
	collectorv1.RegisterTraceServiceServer(srv, &traceReceiver{chain: cw})

	// Graceful shutdown on signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutting down...")
		srv.GracefulStop()
	}()

	log.Printf("bijotel-collector v%s listening OTLP/gRPC on %s (db=%s)", version, addr, *dbPath)
	if err := srv.Serve(lis); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: serve:", err)
		return 3
	}
	return 0
}

// traceReceiver implements the OTLP TraceService Export RPC.
type traceReceiver struct {
	collectorv1.UnimplementedTraceServiceServer
	chain *chain.ChainWriter
}

func (r *traceReceiver) Export(
	_ context.Context,
	req *collectorv1.ExportTraceServiceRequest,
) (*collectorv1.ExportTraceServiceResponse, error) {
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			for _, span := range ss.GetSpans() {
				if !hasGenAIAttribute(span) {
					continue
				}
				if err := r.sealSpan(span); err != nil {
					// Crash-isolation: log and keep going. Returning
					// an error here would cause the OTLP client to
					// retry — that's worse than dropping one span.
					log.Printf("seal error: %v", err)
				}
			}
		}
	}
	return &collectorv1.ExportTraceServiceResponse{}, nil
}

// hasGenAIAttribute returns true iff any attribute key begins with
// "gen_ai." — the v0.1.0 filter rule (design doc §3.2).
func hasGenAIAttribute(span *tracev1.Span) bool {
	for _, attr := range span.GetAttributes() {
		if strings.HasPrefix(attr.GetKey(), "gen_ai.") {
			return true
		}
	}
	return false
}

// sealSpan converts an OTLP span into a chain.SpanRecord and asks the
// chain writer to seal it. Returns the writer's error (if any).
func (r *traceReceiver) sealSpan(span *tracev1.Span) error {
	rec := chain.SpanRecord{
		Name:        span.GetName(),
		Kind:        kindName(span.GetKind()),
		Attributes:  attributesToMap(span.GetAttributes()),
		StatusCode:  statusName(span.GetStatus()),
		StatusDescription: getStatusDescription(span.GetStatus()),
		StartTimeNs: int64(span.GetStartTimeUnixNano()),
		EndTimeNs:   int64(span.GetEndTimeUnixNano()),
		TraceID:     hexBytes(span.GetTraceId()),
		SpanID:      hexBytes(span.GetSpanId()),
	}
	if rec.EndTimeNs == 0 {
		// OTLP says either start or end may be unset for in-flight
		// spans. We require end for sealing — fall back to start.
		rec.EndTimeNs = rec.StartTimeNs
	}
	_, err := r.chain.Seal(rec)
	return err
}

// attributesToMap converts OTLP KeyValue list to Go map[string]interface{}.
// Only the four scalar AnyValue variants are emitted; nested
// arrays/maps fall through (we drop them rather than guess at JCS
// shape — v0.1.0 keeps the body simple).
func attributesToMap(kvs []*commonv1.KeyValue) map[string]interface{} {
	out := make(map[string]interface{}, len(kvs))
	for _, kv := range kvs {
		v := kv.GetValue()
		if v == nil {
			continue
		}
		switch x := v.GetValue().(type) {
		case *commonv1.AnyValue_StringValue:
			out[kv.GetKey()] = x.StringValue
		case *commonv1.AnyValue_IntValue:
			out[kv.GetKey()] = x.IntValue
		case *commonv1.AnyValue_DoubleValue:
			out[kv.GetKey()] = x.DoubleValue
		case *commonv1.AnyValue_BoolValue:
			out[kv.GetKey()] = x.BoolValue
		default:
			// arrays / kvlists / bytes — skip in v0.1.0; document.
		}
	}
	return out
}

func kindName(k tracev1.Span_SpanKind) string {
	switch k {
	case tracev1.Span_SPAN_KIND_CLIENT:
		return "CLIENT"
	case tracev1.Span_SPAN_KIND_SERVER:
		return "SERVER"
	case tracev1.Span_SPAN_KIND_INTERNAL:
		return "INTERNAL"
	case tracev1.Span_SPAN_KIND_PRODUCER:
		return "PRODUCER"
	case tracev1.Span_SPAN_KIND_CONSUMER:
		return "CONSUMER"
	default:
		return ""
	}
}

func statusName(s *tracev1.Status) string {
	if s == nil {
		return ""
	}
	switch s.GetCode() {
	case tracev1.Status_STATUS_CODE_OK:
		return "OK"
	case tracev1.Status_STATUS_CODE_ERROR:
		return "ERROR"
	default:
		return ""
	}
}

func getStatusDescription(s *tracev1.Status) string {
	if s == nil {
		return ""
	}
	return s.GetMessage()
}

// hexBytes returns lowercase hex of b. Empty input → empty string.
func hexBytes(b []byte) string {
	const hexChars = "0123456789abcdef"
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0f]
	}
	return string(out)
}
