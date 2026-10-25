package client

import (
	"strings"
	"testing"

	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

func TestDocumentAttachmentPreservesFilenameOnWire(t *testing.T) {
	const path = "/private/uploads/Contract Brăila-v2.1.DOCX"
	mediaType, mimeType := mediaTypeFromExt(path)
	if mediaType != whatsmeow.MediaDocument {
		t.Fatalf("DOCX classified as %q", mediaType)
	}
	msg := &waProto.Message{DocumentMessage: documentMessage(path, "Revizuit", mimeType, whatsmeow.UploadResponse{
		URL: "https://example.invalid/media", DirectPath: "/media", FileLength: 42389,
		FileSHA256: []byte{1, 2, 3}, MediaKey: []byte{4, 5, 6},
	})}
	wire, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var received waProto.Message
	if err := proto.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}
	doc := received.GetDocumentMessage()
	if doc.GetFileName() != "Contract Brăila-v2.1.DOCX" {
		t.Fatalf("recipient filename = %q", doc.GetFileName())
	}
	if doc.GetMimetype() != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Fatalf("recipient MIME type = %q", doc.GetMimetype())
	}
	if doc.GetCaption() != "Revizuit" || doc.GetFileLength() != 42389 || string(doc.GetFileSHA256()) != string([]byte{1, 2, 3}) {
		t.Fatal("attachment metadata changed")
	}
	if _, got := mediaTypeFromExt("unknown.bin"); got != "application/octet-stream" {
		t.Fatalf("unknown extension fallback = %q", got)
	}
}

// TestParseRecipient covers the recipient-string → types.JID conversion used
// by every send tool. The headline behaviour: a leading `+` on a bare phone
// number is stripped (so E.164-with-plus is accepted as a courtesy), and any
// other non-digit input on the bare-number path is rejected with a clear
// error instead of silently constructing an invalid JID. Fully-qualified JIDs
// containing `@` are delegated to whatsmeow's own parser unchanged.
func TestParseRecipient(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantUser   string
		wantServer string
		wantErr    string // substring expected in error message when set
	}{
		{
			name:       "bare digits",
			in:         "447967960994",
			wantUser:   "447967960994",
			wantServer: types.DefaultUserServer,
		},
		{
			name:       "leading plus is stripped",
			in:         "+447967960994",
			wantUser:   "447967960994",
			wantServer: types.DefaultUserServer,
		},
		{
			name:    "empty rejected",
			in:      "",
			wantErr: "recipient",
		},
		{
			name:    "bare plus rejected",
			in:      "+",
			wantErr: "recipient",
		},
		{
			name:    "spaces rejected",
			in:      "447 967 960994",
			wantErr: "recipient",
		},
		{
			name:    "punctuation rejected",
			in:      "447-967-960994",
			wantErr: "recipient",
		},
		{
			name:    "plus with spaces rejected",
			in:      "+44 7967 960994",
			wantErr: "recipient",
		},
		{
			name:    "non-digit rejected",
			in:      "abc",
			wantErr: "recipient",
		},
		{
			name:       "fully qualified user JID passes through",
			in:         "447967960994@s.whatsapp.net",
			wantUser:   "447967960994",
			wantServer: types.DefaultUserServer,
		},
		{
			name:       "group JID passes through",
			in:         "120363025246125486@g.us",
			wantUser:   "120363025246125486",
			wantServer: types.GroupServer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRecipient(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseRecipient(%q): want error containing %q, got JID %+v", tc.in, tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseRecipient(%q): error = %q, want substring %q", tc.in, err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRecipient(%q): unexpected error %v", tc.in, err)
			}
			if got.User != tc.wantUser {
				t.Errorf("parseRecipient(%q): User = %q, want %q", tc.in, got.User, tc.wantUser)
			}
			if got.Server != tc.wantServer {
				t.Errorf("parseRecipient(%q): Server = %q, want %q", tc.in, got.Server, tc.wantServer)
			}
		})
	}
}
