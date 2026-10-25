package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestMediaRetryStoreScopedIdentity(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	key, sha, enc := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	for i, chat := range []string{"first@s.whatsapp.net", "second@s.whatsapp.net"} {
		if err := s.StoreChat(chat, "fixture", time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := s.StoreMessage(ctx, Message{ID: "same-id", ChatJID: chat, Sender: "sender", Timestamp: time.Now(),
			IsFromMe: i == 0, MediaType: "document", Filename: "report.pdf", URL: "https://example.invalid/old", DirectPath: "/old?sig=original"}, key, sha, enc, 42); err != nil {
			t.Fatal(err)
		}
	}
	source, err := s.GetMediaRetrySource(ctx, "same-id", "second@s.whatsapp.net")
	if err != nil || source.IsFromMe || source.Sender != "sender" {
		t.Fatalf("source identity: %+v %v", source, err)
	}
	if err := s.UpdateMediaDirectPath(ctx, "same-id", "first@s.whatsapp.net", "/new?sig=refreshed", key, sha, enc); err != nil {
		t.Fatal(err)
	}
	for i, chat := range []string{"first@s.whatsapp.net", "second@s.whatsapp.net"} {
		_, _, url, path, mk, gotSHA, gotEnc, size, err := s.GetMediaInfo("same-id", chat)
		want := "/old?sig=original"
		if i == 0 {
			want = "/new?sig=refreshed"
		}
		if err != nil || path != want || url != "https://example.invalid/old" || size != 42 || !bytes.Equal(mk, key) || !bytes.Equal(gotSHA, sha) || !bytes.Equal(gotEnc, enc) {
			t.Fatalf("wrong metadata for %s", chat)
		}
	}
	if err := s.UpdateMediaDirectPath(ctx, "same-id", "first@s.whatsapp.net", "/bad?sig=stale", bytes.Repeat([]byte{9}, 32), sha, enc); err == nil {
		t.Fatal("stale response changed media")
	}
	if err := s.UpdateMediaDirectPath(ctx, "absent", "first@s.whatsapp.net", "/bad?sig=stale", key, sha, enc); err == nil {
		t.Fatal("missing message reported success")
	}
	_, _, _, path, _, _, _, _, err := s.GetMediaInfo("same-id", "first@s.whatsapp.net")
	if err != nil || path != "/new?sig=refreshed" {
		t.Fatalf("stale update changed path: %q %v", path, err)
	}
}
