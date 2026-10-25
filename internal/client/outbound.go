package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"

	"github.com/sealjay/mcp-whatsapp/internal/outbound"
	"github.com/sealjay/mcp-whatsapp/internal/security"
)

// outboundRootHint is the remedy for media_path errors when a dedicated
// outbound root is configured.
const outboundRootHint = "stage a copy under that root with `whatsapp-mcp outbound stage` (WHATSAPP_MCP_OUTBOUND_ROOT)"

// waSender is the part of whatsmeow the send path uses; tests substitute it.
type waSender interface {
	IsConnected() bool
	Upload(ctx context.Context, plaintext []byte, appInfo whatsmeow.MediaType) (whatsmeow.UploadResponse, error)
	SendMessage(ctx context.Context, to types.JID, message *waProto.Message, extra ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error)
}

func (c *Client) transport() waSender {
	if c.sender != nil {
		return c.sender
	}
	return c.wa
}

// OutboundMedia is a file opened for sending: the bytes to upload, the
// name WhatsApp shows, and the descriptor whose shared lock tells the
// staging helper that a send is still in progress. Close it once the send
// has returned.
type OutboundMedia struct {
	Path string // resolved path inside the outbound root
	Name string // file name of the message: document FileName/Title, MIME by extension
	Data []byte // bytes to upload; send_audio_message replaces them with transcoded audio
	file *os.File
}

// Close releases the in-flight lock.
func (m *OutboundMedia) Close() error {
	if m == nil || m.file == nil {
		return nil
	}
	err := m.file.Close()
	m.file = nil
	return err
}

// OpenOutboundMedia opens media_path for a send and reads it.
//
// Without WHATSAPP_MCP_OUTBOUND_ROOT the file must sit under the media
// root, as before. With it, the outbound root is the only root, the path
// must be absolute and the file may have no other hard link, so neither a
// file in the inbound root nor a link to a document elsewhere is sendable.
// In both modes the open is confined to the root (see security.OpenRegular)
// and the bytes uploaded are the ones read from that descriptor.
func (c *Client) OpenOutboundMedia(userPath string) (*OutboundMedia, error) {
	strict := c.outboundRoot != ""
	root := c.allowedMediaRoot
	opts := security.OpenOptions{Field: "media_path", Hint: security.MediaRootHint}
	if strict {
		root = c.outboundRoot
		opts.Hint = outboundRootHint
		opts.RequireAbs, opts.SingleLink = true, true
	}
	f, resolved, err := security.OpenRegular(userPath, root, opts)
	if err != nil {
		if strict && errors.Is(err, security.ErrOutsideRoot) && security.Within(resolved, c.allowedMediaRoot) {
			err = fmt.Errorf("%w; files in the inbound media root are not sendable while WHATSAPP_MCP_OUTBOUND_ROOT is set, including received media", err)
		}
		return nil, err
	}
	if err := outbound.LockInFlight(f); err != nil {
		if errors.Is(err, outbound.ErrBusy) {
			f.Close()
			return nil, fmt.Errorf("media_path %q is being moved to the Trash by the staging helper; stage a new copy", resolved)
		}
		if strict {
			f.Close()
			return nil, fmt.Errorf("lock media_path %q: %w", resolved, err)
		}
		c.log.Warnf("media_path lock unavailable (%v); sending without the in-flight marker", err)
	}
	// The cleanup holds its lock while it moves the directory, so a file
	// that is no longer at its path once we hold ours was cleaned up.
	opened, err := f.Stat()
	current, serr := os.Stat(resolved)
	if err != nil || serr != nil || !os.SameFile(opened, current) {
		f.Close()
		return nil, fmt.Errorf("media_path %q changed while it was being opened; stage it again", resolved)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read media file: %w", err)
	}
	return &OutboundMedia{Path: resolved, Name: filepath.Base(resolved), Data: data, file: f}, nil
}

// OpenDownloadedMedia opens a Path returned by Download for reading.
// fromOutput says whether the download wrote to output_path (confined to
// the inbound media root) or only to the cache (confined to the store).
// The path must name a regular file, not a symlink, so the inline bytes of
// download_media can never come from outside those roots.
func (c *Client) OpenDownloadedMedia(path string, fromOutput bool) (*os.File, error) {
	root := c.allowedMediaRoot
	if !fromOutput {
		root = c.store.Dir()
	}
	if root == "" {
		return nil, errors.New("no media root configured")
	}
	t, err := security.ResolveTarget("path", path, root)
	if err != nil {
		return nil, err
	}
	return t.OpenRegular()
}
