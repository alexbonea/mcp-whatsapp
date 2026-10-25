package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"

	"github.com/sealjay/mcp-whatsapp/internal/outbound"
	"github.com/sealjay/mcp-whatsapp/internal/ratelimit"
	"github.com/sealjay/mcp-whatsapp/internal/security"
	"github.com/sealjay/mcp-whatsapp/internal/store"
)

// fakeSender stands in for the WhatsApp connection. It records uploads
// and messages, and can fail either step or hold SendMessage open.
type fakeSender struct {
	mu        sync.Mutex
	uploadErr error
	sendErr   error
	started   chan struct{} // receives once SendMessage is entered
	release   chan struct{} // when set, SendMessage waits for it
	uploads   [][]byte
	messages  []*waProto.Message
}

func (f *fakeSender) IsConnected() bool { return true }

func (f *fakeSender) Upload(_ context.Context, data []byte, _ whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uploadErr != nil {
		return whatsmeow.UploadResponse{}, f.uploadErr
	}
	f.uploads = append(f.uploads, append([]byte(nil), data...))
	sum := sha256.Sum256(data)
	return whatsmeow.UploadResponse{
		URL: "https://mmg.example.invalid/m", DirectPath: "/m", MediaKey: []byte{1},
		FileEncSHA256: []byte{2}, FileSHA256: sum[:], FileLength: uint64(len(data)),
	}, nil
}

func (f *fakeSender) SendMessage(_ context.Context, _ types.JID, msg *waProto.Message, _ ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
	f.mu.Lock()
	f.messages = append(f.messages, msg)
	started, release, err := f.started, f.release, f.sendErr
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}
	if err != nil {
		return whatsmeow.SendResponse{}, err
	}
	return whatsmeow.SendResponse{ID: "3EB0FAKE"}, nil
}

type sendFixture struct {
	t        *testing.T
	inbound  string
	outbound string
	helper   *outbound.Helper
	tx       *fakeSender
	c        *Client
	trashed  []string
}

// newSendFixture builds a client with an offline whatsmeow device (no
// network), a real message cache, the fake transport and the default rate
// limiter. strict selects WHATSAPP_MCP_OUTBOUND_ROOT mode.
func newSendFixture(t *testing.T, strict bool) *sendFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &sendFixture{
		t:        t,
		inbound:  filepath.Join(base, "inbox", "attachments", "whatsapp"),
		outbound: filepath.Join(base, "state", "outbound"),
		tx:       &fakeSender{},
	}
	storeDir := filepath.Join(base, "state", "store")
	trashDir := filepath.Join(base, "Trash")
	for _, d := range []string{f.inbound, f.outbound, storeDir, trashDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	container, err := sqlstore.New(context.Background(), "sqlite3", "file:"+filepath.Join(storeDir, "whatsapp.db")+"?_foreign_keys=on", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = container.Close() })
	st, err := store.Open(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	device := container.NewDevice()
	device.ID = &types.JID{User: "40700000000", Device: 1, Server: types.DefaultUserServer}
	device.Account = &waAdv.ADVSignedDeviceIdentity{
		Details: []byte{0}, AccountSignature: make([]byte, 64), AccountSignatureKey: make([]byte, 32), DeviceSignature: make([]byte, 64),
	}
	if err := container.PutDevice(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	f.c = &Client{
		wa:               whatsmeow.NewClient(device, nil),
		store:            st,
		log:              NewStderrLogger("test", "ERROR", false),
		redactor:         &security.Redactor{},
		allowedMediaRoot: f.inbound,
		limiter:          ratelimit.New(ratelimit.DefaultConfig()),
		sender:           f.tx,
	}
	if strict {
		f.c.outboundRoot = f.outbound
	}
	f.helper = &outbound.Helper{Root: f.outbound, Trash: func(p string) error {
		f.trashed = append(f.trashed, p)
		return os.Rename(p, filepath.Join(trashDir, filepath.Base(p)))
	}}
	return f
}

func (f *sendFixture) stage(name, content string) *outbound.StageResult {
	f.t.Helper()
	src := filepath.Join(f.t.TempDir(), name)
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	res, err := f.helper.Stage(src, "")
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

// sendFile mirrors the send_file handler: open, send, close.
func (f *sendFixture) sendFile(path string) (SendResult, error) {
	m, err := f.c.OpenOutboundMedia(path)
	if err != nil {
		return SendResult{}, err
	}
	defer m.Close()
	return f.c.SendMediaWithOptions(context.Background(), SendMediaOptions{
		Recipient: "40700000001", Caption: "Actele cerute", Media: m,
	}), nil
}

func TestSendStagedDocument_Success(t *testing.T) {
	f := newSendFixture(t, true)
	const name = "Contract Brăila v2 (semnat).pdf"
	staged := f.stage(name, "%PDF-authorised")

	r, err := f.sendFile(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Success || r.ID != "3EB0FAKE" || r.Uncertain {
		t.Fatalf("result = %+v", r)
	}
	if r.FileSHA256 != staged.SHA256 || r.FileLength != uint64(staged.Size) {
		t.Fatalf("result digest %s/%d, staged %s/%d", r.FileSHA256, r.FileLength, staged.SHA256, staged.Size)
	}
	if len(f.tx.uploads) != 1 || string(f.tx.uploads[0]) != "%PDF-authorised" {
		t.Fatalf("uploaded %q", f.tx.uploads)
	}
	doc := f.tx.messages[0].GetDocumentMessage()
	if doc.GetTitle() != name || doc.GetCaption() != "Actele cerute" {
		t.Fatalf("document message: title %q caption %q", doc.GetTitle(), doc.GetCaption())
	}
	// The send has returned, so the copy is no longer held.
	if _, err := f.helper.Cleanup(staged.OpDir); err != nil {
		t.Fatalf("cleanup after success: %v", err)
	}
}

func TestSendStagedDocument_RateLimitedIsDefiniteAndUploadsNothing(t *testing.T) {
	f := newSendFixture(t, true)
	first := f.stage("a.pdf", "a")
	if r, _ := f.sendFile(first.Path); !r.Success {
		t.Fatalf("first send: %+v", r)
	}
	second := f.stage("b.pdf", "b")
	r, err := f.sendFile(second.Path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Success || r.Uncertain || !strings.Contains(r.Message, "rate limited") || !strings.Contains(r.Message, "retry in") {
		t.Fatalf("result = %+v", r)
	}
	if len(f.tx.uploads) != 1 {
		t.Fatalf("refused send uploaded media (%d uploads)", len(f.tx.uploads))
	}
	if _, err := f.helper.Cleanup(second.OpDir); err != nil {
		t.Fatalf("cleanup after refusal: %v", err)
	}
}

func TestSendStagedDocument_UploadFailureIsDefinite(t *testing.T) {
	f := newSendFixture(t, true)
	f.tx.uploadErr = errors.New("media conn refused")
	staged := f.stage("a.pdf", "a")
	r, err := f.sendFile(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Success || r.Uncertain || !strings.Contains(r.Message, "uploading") {
		t.Fatalf("result = %+v", r)
	}
	if len(f.tx.messages) != 0 {
		t.Fatal("message sent after a failed upload")
	}
}

// A timeout waiting for WhatsApp's ack can follow a send that went out;
// the result must say so instead of reading as a clean failure.
func TestSendStagedDocument_TimeoutAfterAcceptanceIsUncertain(t *testing.T) {
	f := newSendFixture(t, true)
	f.tx.sendErr = whatsmeow.ErrMessageTimedOut
	staged := f.stage("a.pdf", "a")
	r, err := f.sendFile(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Success || !r.Uncertain || r.ID != "" {
		t.Fatalf("result = %+v", r)
	}
}

// While a send is in flight the staging helper must refuse to clean up,
// whatever the MCP transport has told the agent; once the daemon returns
// the copy is free again.
func TestSendStagedDocument_InFlightBlocksCleanup(t *testing.T) {
	f := newSendFixture(t, true)
	f.tx.started = make(chan struct{}, 1)
	f.tx.release = make(chan struct{})
	staged := f.stage("a.pdf", "a")

	done := make(chan SendResult, 1)
	go func() {
		r, err := f.sendFile(staged.Path)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	select {
	case <-f.tx.started:
	case <-time.After(10 * time.Second):
		t.Fatal("send did not start")
	}
	if _, err := f.helper.Cleanup(staged.OpDir); !errors.Is(err, outbound.ErrBusy) {
		t.Fatalf("cleanup during the send: want ErrBusy, got %v", err)
	}
	if sw, _ := f.helper.Sweep(); len(sw.Recovered) != 0 {
		t.Fatalf("sweep recovered an active operation: %+v", sw)
	}
	close(f.tx.release)
	if r := <-done; !r.Success {
		t.Fatalf("send = %+v", r)
	}
	if _, err := f.helper.Cleanup(staged.OpDir); err != nil {
		t.Fatalf("cleanup after the send returned: %v", err)
	}
}

func TestOpenOutboundMedia_RefusesCopyBeingCleanedUp(t *testing.T) {
	f := newSendFixture(t, true)
	staged := f.stage("a.pdf", "a")
	cleaner, err := os.Open(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleaner.Close()
	// What trashOp holds while it moves the directory.
	if err := lockExclusiveForTest(cleaner); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.OpenOutboundMedia(staged.Path); err == nil || !strings.Contains(err.Error(), "Trash") {
		t.Fatalf("want cleanup-in-progress refusal, got %v", err)
	}
}

// With the dedicated root, nothing outside it is sendable: not received
// media in the inbound root, not a hard link to a document, not a
// relative path.
func TestOpenOutboundMedia_StrictRoot(t *testing.T) {
	f := newSendFixture(t, true)
	received := filepath.Join(f.inbound, "2026-10-25-broker", "scan.pdf")
	if err := os.MkdirAll(filepath.Dir(received), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(received, []byte("received"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.c.OpenOutboundMedia(received)
	if !errors.Is(err, security.ErrOutsideRoot) || !strings.Contains(err.Error(), "inbound media root") || !strings.Contains(err.Error(), "outbound stage") {
		t.Fatalf("inbound file: %v", err)
	}

	doc := filepath.Join(t.TempDir(), "bhq-doc.pdf")
	if err := os.WriteFile(doc, []byte("bhq"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.outbound, "linked.pdf")
	if err := os.Link(doc, link); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if _, err := f.c.OpenOutboundMedia(link); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard link: %v", err)
	}

	staged := f.stage("rel.pdf", "rel")
	t.Chdir(f.outbound)
	rel, _ := filepath.Rel(f.outbound, staged.Path)
	if _, err := f.c.OpenOutboundMedia(rel); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path: %v", err)
	}
}

// Without WHATSAPP_MCP_OUTBOUND_ROOT the legacy behaviour holds: files in
// the media root, hard-linked downloads included, remain sendable.
func TestOpenOutboundMedia_LegacyRoot(t *testing.T) {
	f := newSendFixture(t, false)
	cache := filepath.Join(t.TempDir(), "cache.jpg")
	if err := os.WriteFile(cache, []byte("JPEG"), 0o600); err != nil {
		t.Fatal(err)
	}
	received := filepath.Join(f.inbound, "photo.jpg")
	if err := os.Link(cache, received); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	m, err := f.c.OpenOutboundMedia(received)
	if err != nil {
		t.Fatalf("legacy root refused a hard-linked download: %v", err)
	}
	defer m.Close()
	if string(m.Data) != "JPEG" || m.Name != "photo.jpg" {
		t.Fatalf("media = %q %q", m.Name, m.Data)
	}
	outside := filepath.Join(f.outbound, "x.pdf")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.OpenOutboundMedia(outside); !errors.Is(err, security.ErrOutsideRoot) {
		t.Fatalf("legacy mode accepted a path outside the media root: %v", err)
	}
}

func TestSendResultJSONKeepsLegacyShapeForText(t *testing.T) {
	r := SendResult{Success: true, Message: "Message sent to x", ID: "1"}
	b, err := jsonMarshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"Success":true,"Message":"Message sent to x","ID":"1"}` {
		t.Fatalf("text send result changed shape: %s", b)
	}
	sum := sha256.Sum256([]byte("x"))
	b, _ = jsonMarshal(SendResult{Success: true, ID: "1", FileSHA256: hex.EncodeToString(sum[:]), FileLength: 1})
	if !strings.Contains(string(b), `"FileSHA256"`) || !strings.Contains(string(b), `"FileLength":1`) {
		t.Fatalf("media fields missing: %s", b)
	}
}

func lockExclusiveForTest(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
