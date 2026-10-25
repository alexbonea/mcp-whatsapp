package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waMmsRetry"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

type mediaRetryKey struct{ chat, id string }

type mediaRetryCall struct {
	media     *MediaDownloader
	cacheChat string             // original database key, which may still be an LID
	info      *types.MessageInfo // guarded by mediaRetryMu; set before requesting
	events    chan *events.MediaRetry
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int    // guarded by mediaRetryMu
	data      []byte // published by closing done
	err       error
}

func (c *Client) fetchMedia(ctx context.Context, media *MediaDownloader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.downloadMedia != nil {
		return c.downloadMedia(ctx, media)
	}
	if c.wa == nil {
		return nil, errors.New("media downloader is unavailable")
	}
	return c.wa.Download(ctx, media)
}

func isRecoverableMediaError(err error) bool {
	return errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith403) ||
		errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith404) ||
		errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith410)
}

// Never return arbitrary transport errors: they can embed signed CDN URLs.
// A 403 alone does not distinguish expiry from another CDN refusal.
func safeMediaError(err error) error {
	var httpErr whatsmeow.DownloadHTTPError
	if errors.As(err, &httpErr) && httpErr.Response != nil {
		if isRecoverableMediaError(err) {
			return fmt.Errorf("media server returned HTTP %d (the link may be expired or unavailable)", httpErr.StatusCode)
		}
		return fmt.Errorf("media server returned HTTP %d", httpErr.StatusCode)
	}
	for _, known := range []error{context.Canceled, context.DeadlineExceeded,
		whatsmeow.ErrInvalidMediaSHA256, whatsmeow.ErrInvalidMediaEncSHA256,
		whatsmeow.ErrInvalidMediaHMAC, whatsmeow.ErrTooShortFile, whatsmeow.ErrNoURLPresent} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("media transfer failed")
}

func sameMedia(a, b *MediaDownloader) bool {
	return bytes.Equal(a.MediaKey, b.MediaKey) && bytes.Equal(a.FileSHA256, b.FileSHA256) &&
		bytes.Equal(a.FileEncSHA256, b.FileEncSHA256) && a.FileLength == b.FileLength
}

// recoverMedia shares one bounded protocol request and redownload across
// simultaneous callers. A cancelled caller does not abort other waiters; the
// last caller cancels the worker. No WhatsApp chat message/read receipt is sent.
func (c *Client) recoverMedia(ctx context.Context, id, chat string, media *MediaDownloader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := mediaRetryKey{c.store.ResolveLIDToJID(chat), id}
	c.mediaRetryMu.Lock()
	call := c.mediaRetries[key]
	if call != nil && !sameMedia(call.media, media) {
		c.mediaRetryMu.Unlock()
		return nil, errors.New("media metadata changed during recovery; try again")
	}
	if call == nil {
		timeout := c.mediaRetryTimeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		retryCtx, cancel := context.WithTimeout(context.Background(), timeout)
		call = &mediaRetryCall{media: media, cacheChat: chat, events: make(chan *events.MediaRetry, 1), done: make(chan struct{}), cancel: cancel}
		if c.mediaRetries == nil {
			c.mediaRetries = make(map[mediaRetryKey]*mediaRetryCall)
		}
		c.mediaRetries[key] = call
		go func() {
			call.data, call.err = c.retryMediaOnce(retryCtx, key, call)
			cancel()
			c.mediaRetryMu.Lock()
			if c.mediaRetries[key] == call {
				delete(c.mediaRetries, key)
			}
			close(call.done)
			c.mediaRetryMu.Unlock()
		}()
	}
	call.waiters++
	c.mediaRetryMu.Unlock()
	defer func() {
		c.mediaRetryMu.Lock()
		call.waiters--
		if call.waiters == 0 {
			call.cancel()
			if c.mediaRetries[key] == call {
				delete(c.mediaRetries, key)
			}
		}
		c.mediaRetryMu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		return call.data, call.err
	}
}

// The event handler routes notifications using the local LID map. Waiting,
// decryption and downloads run in the worker, never on the event goroutine.
func (c *Client) handleMediaRetry(evt *events.MediaRetry) {
	key := mediaRetryKey{c.store.ResolveLIDToJID(evt.ChatID.ToNonAD().String()), evt.MessageID}
	c.mediaRetryMu.Lock()
	defer c.mediaRetryMu.Unlock()
	if call := c.mediaRetries[key]; call != nil {
		if call.info == nil || evt.FromMe != call.info.IsFromMe {
			return
		}
		if call.info.IsGroup && c.store.ResolveLIDToJID(evt.SenderID.ToNonAD().String()) != c.store.ResolveLIDToJID(call.info.Sender.ToNonAD().String()) {
			return
		}
		select {
		case call.events <- evt:
		default:
		}
	}
}

func (c *Client) retryMediaOnce(ctx context.Context, key mediaRetryKey, call *mediaRetryCall) ([]byte, error) {
	media := *call.media // do not mutate a caller's downloader
	// Another caller may have refreshed the address since the initial failure.
	_, _, cachedURL, path, mk, sha, encSHA, size, err := c.store.GetMediaInfo(key.id, call.cacheChat)
	if err != nil {
		return nil, errors.New("could not reload cached media metadata")
	}
	current := &MediaDownloader{MediaKey: mk, FileSHA256: sha, FileEncSHA256: encSHA, FileLength: size}
	if !sameMedia(&media, current) {
		return nil, errors.New("media metadata changed during recovery; try again")
	}
	if path = preferredDirectPath(path, cachedURL); path != media.DirectPath {
		media.DirectPath = path
		data, err := c.fetchMedia(ctx, &media)
		if err == nil {
			return data, validateMediaPayload(data, media.FileLength, media.FileSHA256)
		}
		if !isRecoverableMediaError(err) {
			return nil, safeMediaError(err)
		}
	}
	source, err := c.store.GetMediaRetrySource(ctx, key.id, call.cacheChat)
	if err != nil {
		return nil, errors.New("could not load media sender and direction")
	}
	chat, err := types.ParseJID(call.cacheChat)
	if err != nil || chat.User == "" {
		return nil, errors.New("invalid media chat")
	}
	info := &types.MessageInfo{ID: key.id, Timestamp: source.Timestamp,
		MessageSource: types.MessageSource{Chat: chat, IsFromMe: source.IsFromMe, IsGroup: chat.Server == types.GroupServer}}
	if info.IsGroup {
		sender := source.Sender
		if !strings.Contains(sender, "@") {
			// Older cache rows contain only the user part. Resolve a known LID first.
			sender = c.store.ResolveLIDToJID(sender + "@lid")
			if strings.HasSuffix(sender, "@lid") {
				sender = source.Sender + "@s.whatsapp.net"
			}
		}
		info.Sender, err = types.ParseJID(sender)
		if err != nil || info.Sender.User == "" {
			return nil, errors.New("missing media group sender")
		}
	}
	c.mediaRetryMu.Lock()
	expected := *info
	call.info = &expected
	c.mediaRetryMu.Unlock()
	if err = c.requestMediaRetry(ctx, info, media.MediaKey); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("could not request media from phone; check that WhatsApp is connected")
	}
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, errors.New("phone media recovery timed out; keep the primary phone online and try again")
			}
			return nil, ctx.Err()
		case evt := <-call.events:
			notification, err := whatsmeow.DecryptMediaRetryNotification(evt, media.MediaKey)
			if errors.Is(err, whatsmeow.ErrMediaNotAvailableOnPhone) {
				return nil, err
			}
			if err != nil {
				return nil, errors.New("could not authenticate the phone media response")
			}
			if notification.GetStanzaID() != "" && notification.GetStanzaID() != key.id {
				return nil, errors.New("phone media response refers to another message")
			}
			switch notification.GetResult() {
			case waMmsRetry.MediaRetryNotification_NOT_FOUND:
				return nil, whatsmeow.ErrMediaNotAvailableOnPhone
			case waMmsRetry.MediaRetryNotification_SUCCESS:
			default:
				return nil, errors.New("phone could not re-upload this media")
			}
			path := notification.GetDirectPath()
			if !validRetryPath(path) {
				return nil, errors.New("phone returned an invalid media path")
			}
			media.DirectPath = path
			data, err := c.fetchMedia(ctx, &media) // exactly one attempt with the phone's path
			if err != nil {
				return nil, fmt.Errorf("download after phone response failed: %v", safeMediaError(err))
			}
			if err := validateMediaPayload(data, media.FileLength, media.FileSHA256); err != nil {
				return nil, errors.New("recovered media failed integrity validation")
			}
			if err := c.store.UpdateMediaDirectPath(ctx, key.id, call.cacheChat, path, media.MediaKey, media.FileSHA256, media.FileEncSHA256); err != nil {
				return nil, errors.New("could not save refreshed media path; cached metadata may have changed")
			}
			return data, nil
		}
	}
}

func validRetryPath(path string) bool {
	u, err := url.ParseRequestURI(path)
	return err == nil && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") &&
		u.Host == "" && u.Scheme == "" && u.RawQuery != "" && !strings.ContainsAny(path, "\r\n")
}

func (c *Client) requestMediaRetry(ctx context.Context, info *types.MessageInfo, mediaKey []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.sendMediaRetry != nil {
		return c.sendMediaRetry(ctx, info, mediaKey)
	}
	if c.wa == nil || !c.wa.IsConnected() {
		return errors.New("not connected")
	}
	// History often arrives under an LID even though our cache uses phone JIDs.
	if info.Chat.Server == types.DefaultUserServer {
		if lid, err := c.wa.Store.LIDs.GetLIDForPN(ctx, info.Chat); err == nil && !lid.IsEmpty() {
			info.Chat = lid
		}
	}
	return c.wa.SendMediaRetryReceipt(ctx, info, mediaKey)
}
