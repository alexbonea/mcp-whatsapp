package client

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	waBinary "go.mau.fi/whatsmeow/binary"
	wmstore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// recordingLogger keeps every formatted log line so a test can observe what
// the whatsmeow client did with a node it was handed.
type recordingLogger struct {
	mu    *sync.Mutex
	lines *[]string
}

func newRecordingLogger() recordingLogger {
	return recordingLogger{mu: &sync.Mutex{}, lines: &[]string{}}
}

func (l recordingLogger) record(level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	*l.lines = append(*l.lines, level+" "+fmt.Sprintf(msg, args...))
}

func (l recordingLogger) Warnf(msg string, args ...any)  { l.record("WARN", msg, args...) }
func (l recordingLogger) Errorf(msg string, args ...any) { l.record("ERROR", msg, args...) }
func (l recordingLogger) Infof(msg string, args ...any)  { l.record("INFO", msg, args...) }
func (l recordingLogger) Debugf(msg string, args ...any) { l.record("DEBUG", msg, args...) }
func (l recordingLogger) Sub(string) waLog.Logger        { return l }

func (l recordingLogger) contains(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range *l.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func (l recordingLogger) dump() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(*l.lines, "\n")
}

// TestWhatsmeowAcksStatusNodes guards the whatsmeow pin. The WhatsApp server
// pushes <status> stanzas to linked devices. A client that never acknowledges
// one is dropped about 50 minutes later with
// <stream:error><ack class="status" .../></stream:error>, and the forced
// reconnect stalls offline delivery: on 2026-11-10 group messages stopped
// reaching the local cache. whatsmeow fac667d55293 left <status> unhandled;
// a2381054887e acknowledges it.
//
// With no socket the acknowledgement cannot be sent, so whatsmeow logs the
// failed attempt; that log line is the observable proof that it tried. A
// stanza whatsmeow fails to parse is also answered, but with a parse-error
// NACK logged as "Failed to parse message" first, so the test rejects that
// line to make sure a well-formed <status> gets a plain acknowledgement.
func TestWhatsmeowAcksStatusNodes(t *testing.T) {
	log := newRecordingLogger()
	ownID := types.NewADJID("40700000000", 0, 1)
	wa := whatsmeow.NewClient(&wmstore.Device{ID: &ownID}, log)
	internals := wa.DangerousInternals()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go internals.HandlerQueueLoop(ctx, ctx)

	const id = "STATUSACKTEST1"
	frame, err := waBinary.Marshal(waBinary.Node{
		Tag: "status",
		Attrs: waBinary.Attrs{
			"from": types.NewJID("40700000001", types.DefaultUserServer),
			"id":   id,
			"t":    "1794348000",
			"type": "media",
		},
	})
	if err != nil {
		t.Fatalf("marshal status node: %v", err)
	}
	internals.HandleFrame(ctx, frame)

	want := "Failed to send acknowledgement for status " + id
	deadline := time.Now().Add(2 * time.Second)
	for !log.contains(want) {
		if time.Now().After(deadline) {
			t.Fatalf("whatsmeow did not try to acknowledge a <status> node; log:\n%s", log.dump())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if log.contains("Failed to parse message") {
		t.Fatalf("whatsmeow rejected a well-formed <status> node with a parse-error NACK; log:\n%s", log.dump())
	}
}
