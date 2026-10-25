package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/store"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waMmsRetry"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/gcmutil"
	"go.mau.fi/whatsmeow/util/hkdfutil"
	"google.golang.org/protobuf/proto"
)

const retryID = "TEST-MEDIA-RETRY"
const retryChat = "447700000001@s.whatsapp.net"
const oldMediaPath = "/old?oe=1&oh=old-secret"
const newMediaPath = "/new?oe=ffffffff&oh=new-secret"

var retryPayload = []byte("verified PDF bytes")

func seedRetry(t *testing.T, c *Client, id, chat string, fromMe bool) *MediaDownloader {
	t.Helper()
	key, enc := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	sha := sha256.Sum256(retryPayload)
	if err := c.store.StoreChat(chat, "fixture", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.store.StoreMessage(context.Background(), store.Message{
		ID: id, ChatJID: chat, Sender: "447700000002", Timestamp: time.Now(), IsFromMe: fromMe,
		MediaType: "document", Filename: "report.pdf", URL: "https://mmg.whatsapp.net" + oldMediaPath, DirectPath: oldMediaPath,
	}, key, sha[:], enc, uint64(len(retryPayload))); err != nil {
		t.Fatal(err)
	}
	return &MediaDownloader{URL: "https://mmg.whatsapp.net" + oldMediaPath, DirectPath: oldMediaPath,
		MediaKey: key, FileSHA256: sha[:], FileEncSHA256: enc, FileLength: uint64(len(retryPayload)), MediaType: whatsmeow.MediaDocument}
}

func retryClient(t *testing.T) (*Client, *MediaDownloader) {
	t.Helper()
	c := newClientWithStore(t, newTestStoreWithLIDMap(t, map[string]string{"99887766": "447700000001", "99887767": "447700000002"}))
	c.mediaRetryTimeout = time.Second
	return c, seedRetry(t, c, retryID, retryChat, true)
}

// Real authenticated protocol payload, not a mocked decryptor. Synthetic keys
// and media only; tests never connect to WhatsApp or load an account store.
func retryEvent(t *testing.T, info *types.MessageInfo, key []byte, result waMmsRetry.MediaRetryNotification_ResultType, path string) *events.MediaRetry {
	t.Helper()
	return retryEventWithStanza(t, info, key, result, path, info.ID)
}

func retryEventWithStanza(t *testing.T, info *types.MessageInfo, key []byte, result waMmsRetry.MediaRetryNotification_ResultType, path, stanza string) *events.MediaRetry {
	t.Helper()
	raw, err := proto.Marshal(&waMmsRetry.MediaRetryNotification{StanzaID: proto.String(stanza), Result: result.Enum(), DirectPath: proto.String(path)})
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{3}, 12)
	cipher, err := gcmutil.Encrypt(hkdfutil.SHA256(key, nil, []byte("WhatsApp Media Retry Notification"), 32), iv, raw, []byte(info.ID))
	if err != nil {
		t.Fatal(err)
	}
	return &events.MediaRetry{MessageID: info.ID, ChatID: info.Chat, SenderID: info.Sender, FromMe: info.IsFromMe, IV: iv, Ciphertext: cipher}
}

func mediaPath(t *testing.T, c *Client) string {
	t.Helper()
	_, _, _, p, _, _, _, _, err := c.store.GetMediaInfo(retryID, retryChat)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDownloadRecoversExpiredMedia(t *testing.T) {
	for _, status := range []int{403, 404, 410} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, _ := retryClient(t)
			var downloads, requests atomic.Int32
			c.downloadMedia = func(_ context.Context, m whatsmeow.DownloadableMessage) ([]byte, error) {
				downloads.Add(1)
				if m.GetDirectPath() == oldMediaPath {
					return nil, fmt.Errorf("wrapped: %w", whatsmeow.DownloadHTTPError{Response: &http.Response{StatusCode: status}})
				}
				if m.GetDirectPath() != newMediaPath {
					return nil, errors.New("unexpected path")
				}
				return retryPayload, nil
			}
			c.sendMediaRetry = func(_ context.Context, info *types.MessageInfo, key []byte) error {
				requests.Add(1)
				if info.ID != retryID || info.Chat.String() != retryChat || !info.IsFromMe || info.IsGroup {
					return errors.New("wrong retry identity")
				}
				evt := retryEvent(t, info, key, waMmsRetry.MediaRetryNotification_SUCCESS, newMediaPath)
				// Phone uses LID while the cached DM uses a phone JID.
				evt.ChatID = types.NewJID("99887766", types.HiddenUserServer)
				c.handleMediaRetry(evt) // response can arrive synchronously, before send returns
				return nil
			}
			root := filepath.Join(t.TempDir(), "outputs")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			c.allowedMediaRoot = root
			output := filepath.Join(root, "recovered.pdf")
			result := c.Download(context.Background(), retryID, retryChat, output)
			if !result.Success {
				t.Fatalf("recovery failed: %+v", result)
			}
			data, err := os.ReadFile(result.Path)
			if err != nil || !bytes.Equal(data, retryPayload) {
				t.Fatalf("bad output: %q %v", data, err)
			}
			if mediaPath(t, c) != newMediaPath {
				t.Fatal("new path not persisted")
			}
			again := c.Download(context.Background(), retryID, retryChat, "")
			if !again.Success || requests.Load() != 1 || downloads.Load() != 2 {
				t.Fatalf("cache/retry counts: %+v requests=%d downloads=%d", again, requests.Load(), downloads.Load())
			}
			mode, _ := os.Stat(again.Path)
			if mode.Mode().Perm() != 0600 {
				t.Fatalf("cache mode %v", mode.Mode())
			}
		})
	}
}

func TestMediaRecoveryFailuresAreBoundedAndSafe(t *testing.T) {
	for _, kind := range []string{"phone-missing", "encrypted-not-found", "phone-error", "decrypt", "wrong-stanza", "empty-path", "absolute-path", "timeout", "send-error", "second-403", "bad-payload", "changed-metadata"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := retryClient(t)
			if kind == "timeout" {
				c.mediaRetryTimeout = 30 * time.Millisecond
			}
			var downloads, requests atomic.Int32
			c.downloadMedia = func(_ context.Context, m whatsmeow.DownloadableMessage) ([]byte, error) {
				downloads.Add(1)
				if m.GetDirectPath() == oldMediaPath || kind == "second-403" {
					return nil, whatsmeow.ErrMediaDownloadFailedWith403
				}
				if kind == "bad-payload" {
					return []byte("corrupt"), nil
				}
				return retryPayload, nil
			}
			c.sendMediaRetry = func(_ context.Context, info *types.MessageInfo, key []byte) error {
				requests.Add(1)
				if kind == "timeout" {
					return nil
				}
				if kind == "send-error" {
					return errors.New("secret-token=https://secret.invalid/path?oh=secret")
				}
				result, path := waMmsRetry.MediaRetryNotification_SUCCESS, newMediaPath
				if kind == "encrypted-not-found" {
					result = waMmsRetry.MediaRetryNotification_NOT_FOUND
				}
				if kind == "phone-error" {
					result = waMmsRetry.MediaRetryNotification_GENERAL_ERROR
				}
				if kind == "empty-path" {
					path = ""
				}
				if kind == "absolute-path" {
					path = "https://attacker.invalid/?oh=secret"
				}
				if kind == "wrong-stanza" {
					evt := retryEventWithStanza(t, info, key, result, path, "OTHER")
					c.handleMediaRetry(evt)
					return nil
				}
				evt := retryEvent(t, info, key, result, path)
				if kind == "phone-missing" {
					evt.Ciphertext = nil
					evt.Error = &events.MediaRetryError{Code: 2}
				}
				if kind == "decrypt" {
					evt.Ciphertext[0] ^= 1
				}
				if kind == "changed-metadata" {
					if _, err := c.store.DB().Exec("UPDATE messages SET media_key=? WHERE id=? AND chat_jid=?", bytes.Repeat([]byte{9}, 32), retryID, retryChat); err != nil {
						return err
					}
				}
				c.handleMediaRetry(evt)
				return nil
			}
			got := c.Download(context.Background(), retryID, retryChat, "")
			if got.Success {
				t.Fatalf("unexpected success: %+v", got)
			}
			if requests.Load() != 1 || downloads.Load() > 2 {
				t.Fatalf("unbounded retry: requests %d downloads %d", requests.Load(), downloads.Load())
			}
			if strings.Contains(got.Message, "secret") || strings.Contains(got.Message, "https://") {
				t.Fatalf("leaked diagnostic: %s", got.Message)
			}
			if !strings.Contains(got.Message, "HTTP 403") {
				t.Fatalf("lost original failure: %s", got.Message)
			}
			if kind == "timeout" && !strings.Contains(got.Message, "timed out") {
				t.Fatalf("wrong timeout: %s", got.Message)
			}
			if strings.Contains(kind, "not-found") || kind == "phone-missing" {
				if !strings.Contains(got.Message, "no longer available on phone") {
					t.Fatalf("wrong unavailable error: %s", got.Message)
				}
			}
			if mediaPath(t, c) != oldMediaPath {
				t.Fatal("failed recovery overwrote path")
			}
			files, _ := filepath.Glob(filepath.Join(c.store.Dir(), retryChat, "*", "*"))
			if len(files) != 0 {
				t.Fatalf("failed recovery wrote cache: %v", files)
			}
		})
	}
}

func TestDownloadDoesNotRecoverOtherErrors(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, whatsmeow.ErrInvalidMediaSHA256,
		whatsmeow.DownloadHTTPError{Response: &http.Response{StatusCode: 500}}, errors.New("https://cdn.invalid/?oh=SECRET")} {
		t.Run(err.Error(), func(t *testing.T) {
			c, _ := retryClient(t)
			c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) { return nil, err }
			c.sendMediaRetry = func(context.Context, *types.MessageInfo, []byte) error {
				t.Error("unexpected phone request")
				return nil
			}
			result := c.Download(context.Background(), retryID, retryChat, "")
			if result.Success || strings.Contains(result.Message, "SECRET") {
				t.Fatalf("bad failure: %+v", result)
			}
		})
	}
}

func TestMediaRetryRoutingAndGroups(t *testing.T) {
	c, _ := retryClient(t)
	chat := "123456@g.us"
	media := seedRetry(t, c, retryID, chat, false)
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) { return retryPayload, nil }
	c.sendMediaRetry = func(_ context.Context, info *types.MessageInfo, key []byte) error {
		if !info.IsGroup || info.IsFromMe || info.Sender.String() != "447700000002@s.whatsapp.net" {
			return errors.New("wrong group source")
		}
		valid := retryEvent(t, info, key, waMmsRetry.MediaRetryNotification_SUCCESS, newMediaPath)
		// None of these may occupy the notification slot or complete the request.
		bad := *valid
		bad.MessageID = "OTHER"
		c.handleMediaRetry(&bad)
		bad = *valid
		bad.ChatID = types.NewJID("other", types.GroupServer)
		c.handleMediaRetry(&bad)
		bad = *valid
		bad.FromMe = true
		c.handleMediaRetry(&bad)
		bad = *valid
		bad.SenderID = types.NewJID("other", types.DefaultUserServer)
		c.handleMediaRetry(&bad)
		valid.SenderID = types.NewJID("99887767", types.HiddenUserServer)
		c.handleMediaRetry(valid)
		c.handleMediaRetry(valid) // duplicate must not block event delivery
		return nil
	}
	data, err := c.recoverMedia(context.Background(), retryID, chat, media)
	if err != nil || !bytes.Equal(data, retryPayload) {
		t.Fatalf("group recovery failed: %v", err)
	}
}

// Wait for a specific number of attached callers without timing assumptions.
func waitRetryCall(t *testing.T, c *Client, n int) *mediaRetryCall {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		c.mediaRetryMu.Lock()
		call := c.mediaRetries[mediaRetryKey{retryChat, retryID}]
		ready := call != nil && call.waiters == n
		c.mediaRetryMu.Unlock()
		if ready {
			return call
		}
		select {
		case <-deadline:
			t.Fatal("retry callers did not attach")
			return nil
		case <-time.After(time.Millisecond):
		}
	}
}

func TestMediaRecoveryConcurrentCancellation(t *testing.T) {
	c, media := retryClient(t)
	requested := make(chan *events.MediaRetry, 1)
	var requests atomic.Int32
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) { return retryPayload, nil }
	c.sendMediaRetry = func(_ context.Context, info *types.MessageInfo, key []byte) error {
		requests.Add(1)
		requested <- retryEvent(t, info, key, waMmsRetry.MediaRetryNotification_SUCCESS, newMediaPath)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { _, err := c.recoverMedia(ctx, retryID, retryChat, media); first <- err }()
	evt := <-requested
	go func() { _, err := c.recoverMedia(context.Background(), retryID, retryChat, media); second <- err }()
	waitRetryCall(t, c, 2)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	waitRetryCall(t, c, 1)
	c.handleMediaRetry(evt)
	if err := <-second; err != nil {
		t.Fatalf("remaining caller: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("duplicate request: %d", requests.Load())
	}
	// Stale downloader arriving after completion must reuse persisted path.
	if _, err := c.recoverMedia(context.Background(), retryID, retryChat, media); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("stale concurrent caller requested phone again")
	}
}

func TestMediaRecoveryLastCancellationCleansUp(t *testing.T) {
	c, media := retryClient(t)
	requested := make(chan struct{})
	c.sendMediaRetry = func(context.Context, *types.MessageInfo, []byte) error { close(requested); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := c.recoverMedia(ctx, retryID, retryChat, media); result <- err }()
	<-requested
	call := waitRetryCall(t, c, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-call.done:
	case <-time.After(time.Second):
		t.Fatal("cancelled worker leaked")
	}
	c.mediaRetryMu.Lock()
	remaining := len(c.mediaRetries)
	c.mediaRetryMu.Unlock()
	if remaining != 0 {
		t.Fatalf("pending recovery leaked: %d", remaining)
	}
}

func TestRecoveryWithCachedLIDChat(t *testing.T) {
	c, _ := retryClient(t)
	const lidChat = "99887766@lid"
	media := seedRetry(t, c, "LID-ONLY", lidChat, false)
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) { return retryPayload, nil }
	c.sendMediaRetry = func(_ context.Context, info *types.MessageInfo, key []byte) error {
		if info.Chat.String() != lidChat || info.IsFromMe {
			return errors.New("wrong LID source")
		}
		evt := retryEvent(t, info, key, waMmsRetry.MediaRetryNotification_SUCCESS, newMediaPath)
		evt.ChatID = types.NewJID("447700000001", types.DefaultUserServer)
		c.handleMediaRetry(evt)
		return nil
	}
	if _, err := c.recoverMedia(context.Background(), "LID-ONLY", lidChat, media); err != nil {
		t.Fatal(err)
	}
	_, _, _, path, _, _, _, _, err := c.store.GetMediaInfo("LID-ONLY", lidChat)
	if err != nil || path != newMediaPath {
		t.Fatalf("wrong cached LID update: %q %v", path, err)
	}
}

func TestDownloadDirectPathWithoutURLAndFreshMedia(t *testing.T) {
	for _, kind := range []struct {
		name      string
		mediaType whatsmeow.MediaType
	}{
		{"document", whatsmeow.MediaDocument}, {"image", whatsmeow.MediaImage}, {"audio", whatsmeow.MediaAudio}, {"video", whatsmeow.MediaVideo},
	} {
		t.Run(kind.name, func(t *testing.T) {
			c, _ := retryClient(t)
			if _, err := c.store.DB().Exec("UPDATE messages SET url='', media_type=? WHERE id=? AND chat_jid=?", kind.name, retryID, retryChat); err != nil {
				t.Fatal(err)
			}
			c.downloadMedia = func(_ context.Context, m whatsmeow.DownloadableMessage) ([]byte, error) {
				if m.GetDirectPath() != oldMediaPath || whatsmeow.GetMediaType(m) != kind.mediaType {
					return nil, errors.New("wrong downloader")
				}
				return retryPayload, nil
			}
			c.sendMediaRetry = func(context.Context, *types.MessageInfo, []byte) error {
				t.Error("fresh download asked phone to re-upload")
				return nil
			}
			if r := c.Download(context.Background(), retryID, retryChat, ""); !r.Success {
				t.Fatalf("direct path download: %+v", r)
			}
		})
	}
}

func TestMediaRecoveryDisconnectedAndPreCancelled(t *testing.T) {
	c, media := retryClient(t)
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) {
		return nil, whatsmeow.ErrMediaDownloadFailedWith403
	}
	if r := c.Download(context.Background(), retryID, retryChat, ""); r.Success || !strings.Contains(r.Message, "check that WhatsApp is connected") {
		t.Fatalf("disconnected: %+v", r)
	}
	c.sendMediaRetry = func(context.Context, *types.MessageInfo, []byte) error { t.Error("cancelled request sent"); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.recoverMedia(ctx, retryID, retryChat, media); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRecoveredPathSurvivesStoreReopen(t *testing.T) {
	c, media := retryClient(t)
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) { return retryPayload, nil }
	c.sendMediaRetry = func(_ context.Context, info *types.MessageInfo, key []byte) error {
		c.handleMediaRetry(retryEvent(t, info, key, waMmsRetry.MediaRetryNotification_SUCCESS, newMediaPath))
		return nil
	}
	if _, err := c.recoverMedia(context.Background(), retryID, retryChat, media); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(c.store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again := newClientWithStore(t, reopened)
	again.downloadMedia = func(_ context.Context, m whatsmeow.DownloadableMessage) ([]byte, error) {
		if m.GetDirectPath() != newMediaPath {
			return nil, errors.New("old path after restart")
		}
		return retryPayload, nil
	}
	again.sendMediaRetry = func(context.Context, *types.MessageInfo, []byte) error {
		t.Error("restart lost refreshed path")
		return nil
	}
	if got := again.Download(context.Background(), retryID, retryChat, ""); !got.Success {
		t.Fatalf("restart download: %+v", got)
	}
}
