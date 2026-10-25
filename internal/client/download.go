package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sealjay/mcp-whatsapp/internal/security"
	"go.mau.fi/whatsmeow"
)

// DownloadResult is the public return value from Download.
type DownloadResult struct {
	Success   bool
	Message   string
	MediaType string
	Filename  string
	Path      string
}

// MediaDownloader implements whatsmeow.DownloadableMessage for cached media.
type MediaDownloader struct {
	URL           string
	DirectPath    string
	MediaKey      []byte
	FileLength    uint64
	FileSHA256    []byte
	FileEncSHA256 []byte
	MediaType     whatsmeow.MediaType
}

func (d *MediaDownloader) GetDirectPath() string    { return d.DirectPath }
func (d *MediaDownloader) GetURL() string           { return d.URL }
func (d *MediaDownloader) GetMediaKey() []byte      { return d.MediaKey }
func (d *MediaDownloader) GetFileLength() uint64    { return d.FileLength }
func (d *MediaDownloader) GetFileSHA256() []byte    { return d.FileSHA256 }
func (d *MediaDownloader) GetFileEncSHA256() []byte { return d.FileEncSHA256 }
func (d *MediaDownloader) GetMediaType() whatsmeow.MediaType {
	return d.MediaType
}

// Download fetches media for a previously-cached message and writes it under
// <StoreDir>/<chat_sanitized>/<filename>. If outputPath is non-empty, the
// decrypted bytes are additionally placed at that location (validated against
// the configured media root). The cache is always populated so subsequent
// calls remain idempotent.
func (c *Client) Download(ctx context.Context, messageID, chatJID, outputPath string) DownloadResult {
	// Validate output_path first so a bad path fails the call before any DB
	// or network work. The skip-if-exists check waits until after we have
	// the media metadata (so the success response carries the right fields).
	var resolvedOutput *security.Target
	if outputPath != "" {
		var err error
		resolvedOutput, err = c.ResolveOutputPath(outputPath)
		if err != nil {
			return DownloadResult{Success: false, Message: err.Error()}
		}
	}

	// Look up the cached media fields.
	mediaType, filename, url, directPath, mediaKey, fileSHA256, fileEncSHA256, fileLength, err :=
		c.store.GetMediaInfo(messageID, chatJID)
	if err != nil {
		return DownloadResult{
			Success: false,
			Message: fmt.Sprintf("failed to find message: %v", err),
		}
	}
	if mediaType == "" {
		return DownloadResult{
			Success: false,
			Message: "not a media message",
		}
	}

	// Skip-if-exists at the caller's destination: symmetric with the cache
	// short-circuit below. Idempotent re-calls are a no-op. Only a regular
	// file counts: a symlink there (Syncthing replicates symlinks from the
	// other Mac) would make the result, and the inline bytes read from it,
	// point at a file outside the media root.
	if resolvedOutput != nil {
		info, statErr := resolvedOutput.Lstat()
		switch {
		case statErr == nil && info.Mode().IsRegular():
			return DownloadResult{
				Success:   true,
				Message:   fmt.Sprintf("Successfully downloaded %s media", mediaType),
				MediaType: mediaType,
				Filename:  filename,
				Path:      resolvedOutput.Path,
			}
		case statErr == nil:
			return DownloadResult{Success: false, Message: fmt.Sprintf("output_path %q already exists and is not a regular file; choose a new filename", resolvedOutput.Path)}
		case !errors.Is(statErr, fs.ErrNotExist):
			return DownloadResult{Success: false, Message: fmt.Sprintf("inspect output_path: %v", statErr)}
		}
	}

	storeDir, err := filepath.Abs(c.store.Dir())
	if err != nil {
		return DownloadResult{Success: false, Message: fmt.Sprintf("resolve store dir: %v", err)}
	}
	storeDir = filepath.Clean(storeDir)
	chatDir := filepath.Clean(filepath.Join(storeDir, strings.ReplaceAll(chatJID, ":", "_")))
	if !strings.HasPrefix(chatDir, storeDir+string(filepath.Separator)) {
		return DownloadResult{Success: false, Message: "invalid chat directory: path escapes store"}
	}
	if err := os.MkdirAll(chatDir, 0o700); err != nil {
		return DownloadResult{Success: false, Message: fmt.Sprintf("failed to create chat directory: %v", err)}
	}

	safeName := security.SafeFilename(filename)
	localPath := filepath.Join(chatDir, safeName)
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return DownloadResult{Success: false, Message: fmt.Sprintf("failed to get absolute path: %v", err)}
	}

	// Short-circuit if we already have the file in cache. If output_path is
	// set, materialise it there from the cache (cheap hardlink + copy
	// fallback) and return the output path instead.
	if _, err := os.Stat(localPath); err == nil {
		return finalizeDownload(localPath, absPath, resolvedOutput, mediaType, filename)
	}

	if url == "" || len(mediaKey) == 0 || len(fileSHA256) == 0 || len(fileEncSHA256) == 0 || fileLength == 0 {
		return DownloadResult{Success: false, Message: "incomplete media information for download"}
	}

	c.log.Infof("Attempting to download media for message %s in chat %s...", c.redactor.MsgID(messageID), c.redactor.JID(chatJID))

	var waMediaType whatsmeow.MediaType
	switch mediaType {
	case "image":
		waMediaType = whatsmeow.MediaImage
	case "video":
		waMediaType = whatsmeow.MediaVideo
	case "audio":
		waMediaType = whatsmeow.MediaAudio
	case "document":
		waMediaType = whatsmeow.MediaDocument
	default:
		return DownloadResult{Success: false, Message: fmt.Sprintf("unsupported media type: %s", mediaType)}
	}

	downloader := &MediaDownloader{
		URL:           url,
		DirectPath:    preferredDirectPath(directPath, url),
		MediaKey:      mediaKey,
		FileLength:    fileLength,
		FileSHA256:    fileSHA256,
		FileEncSHA256: fileEncSHA256,
		MediaType:     waMediaType,
	}

	data, err := c.wa.Download(ctx, downloader)
	if err != nil {
		return DownloadResult{Success: false, Message: fmt.Sprintf("failed to download media: %v", err)}
	}

	if err := os.WriteFile(localPath, data, 0o600); err != nil {
		return DownloadResult{Success: false, Message: fmt.Sprintf("failed to save media file: %v", err)}
	}

	c.log.Infof("Successfully downloaded %s media (%d bytes)", mediaType, len(data))
	return finalizeDownload(localPath, absPath, resolvedOutput, mediaType, filename)
}

// finalizeDownload materialises the cached file at resolvedOutput (if set)
// and builds the success DownloadResult. Shared by the cache-hit and
// fresh-download paths in Download, which differ only in the log line
// emitted just before this call.
func finalizeDownload(localPath, absPath string, resolvedOutput *security.Target, mediaType, filename string) DownloadResult {
	returnPath := absPath
	if resolvedOutput != nil {
		if err := placeAtOutput(localPath, resolvedOutput); err != nil {
			return DownloadResult{Success: false, Message: fmt.Sprintf("failed to write output_path: %v", err)}
		}
		returnPath = resolvedOutput.Path
	}
	return DownloadResult{
		Success:   true,
		Message:   fmt.Sprintf("Successfully downloaded %s media", mediaType),
		MediaType: mediaType,
		Filename:  filename,
		Path:      returnPath,
	}
}

// placeAtOutput writes an independent copy of src at dst. Unlike the hard
// link earlier versions made, the copy shares no inode with the private
// cache, so edits, permission changes or moves of the materialised file
// never reach the cache. The file is created exclusively inside the media
// root; if something already sits at dst (a concurrent call won the race),
// a regular file satisfies the request and anything else is an error.
func placeAtOutput(src string, dst *security.Target) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := dst.CreateExclusive()
	if errors.Is(err, fs.ErrExist) {
		if info, lerr := dst.Lstat(); lerr == nil && info.Mode().IsRegular() {
			return nil
		}
		return fmt.Errorf("%q already exists and is not a regular file", dst.Path)
	}
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = dst.Remove()
		return err
	}
	if err := out.Close(); err != nil {
		_ = dst.Remove()
		return err
	}
	return nil
}

// preferredDirectPath picks the value handed to whatsmeow as the download's
// DirectPath. New rows carry a stored directPath captured verbatim from the
// media protobuf (including the signed `?ccb=&oh=&oe=&_nc_sid=` CDN auth
// query), which is authoritative. Legacy rows written before the
// direct_path column existed fall back to parsing URL — the same behaviour
// prior daemon builds had.
func preferredDirectPath(stored, url string) string {
	if stored != "" {
		return stored
	}
	return extractDirectPathFromURL(url)
}

// extractDirectPathFromURL turns a CDN URL into the /direct/path/form that
// whatsmeow's Download requires when the URL does not already contain it.
//
// The query string MUST be preserved: whatsmeow builds the request URL as
// `https://<host><directPath>&hash=…&mms-type=…&__wa-mms=`, which assumes
// directPath already ends in `?ccb=…&oh=…&oe=…&_nc_sid=…` (WhatsApp's signed
// CDN auth params). Stripping the query yields a malformed URL and every
// download returns 403.
func extractDirectPathFromURL(url string) string {
	parts := strings.SplitN(url, ".net/", 2)
	if len(parts) < 2 {
		return url
	}
	return "/" + parts[1]
}
