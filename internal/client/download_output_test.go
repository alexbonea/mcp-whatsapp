package client

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: a symlink already sitting at output_path (Syncthing
// replicates symlinks into the inbox from the other Mac) used to satisfy
// the skip-if-exists check, so download_media reported success with a
// Path whose bytes, inlined for images, came from the link's target.
func TestDownload_OutputPathSymlinkIsRefused(t *testing.T) {
	_, mediaRoot, c := seedCacheHit(t, "447700000099@s.whatsapp.net", "M-SYM-1", "p.jpg")
	secret := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(secret, []byte("PRIVATE-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(mediaRoot, "photo.jpg")
	if err := os.Symlink(secret, out); err != nil {
		t.Fatal(err)
	}

	got := c.Download(context.Background(), "M-SYM-1", "447700000099@s.whatsapp.net", out)
	if got.Success {
		t.Fatalf("symlinked output_path accepted: %+v", got)
	}
	if !strings.Contains(got.Message, "not a regular file") {
		t.Fatalf("unexpected message: %s", got.Message)
	}
	if b, _ := os.ReadFile(secret); string(b) != "PRIVATE-KEY" {
		t.Fatal("symlink target modified")
	}
}

// output_path receives an independent copy: no inode shared with the
// private cache, so editing or moving the materialised file never touches
// the cache.
func TestDownload_OutputPathIsIndependentCopy(t *testing.T) {
	cachePath, mediaRoot, c := seedCacheHit(t, "447700000099@s.whatsapp.net", "M-COPY-1", "p.jpg")
	out := filepath.Join(mediaRoot, "received.jpg")

	got := c.Download(context.Background(), "M-COPY-1", "447700000099@s.whatsapp.net", out)
	if !got.Success {
		t.Fatalf("download failed: %+v", got)
	}
	cacheInfo, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	outInfo, err := os.Lstat(out)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(cacheInfo, outInfo) {
		t.Fatal("output_path shares the cache inode")
	}
	if outInfo.Mode().Perm() != 0o600 {
		t.Fatalf("output mode %v", outInfo.Mode().Perm())
	}
	if err := os.WriteFile(out, []byte("EDITED"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cachePath); string(b) != "PRETEND-JPEG-BYTES" {
		t.Fatalf("editing output_path changed the cache: %q", b)
	}
}

// The inline bytes of download_media are read through OpenDownloadedMedia:
// regular files inside the root only, never a symlink.
func TestOpenDownloadedMedia_Confinement(t *testing.T) {
	cachePath, mediaRoot, c := seedCacheHit(t, "447700000099@s.whatsapp.net", "M-INL-1", "p.jpg")
	out := filepath.Join(mediaRoot, "ok.jpg")
	if got := c.Download(context.Background(), "M-INL-1", "447700000099@s.whatsapp.net", out); !got.Success {
		t.Fatalf("download: %+v", got)
	}
	f, err := c.OpenDownloadedMedia(out, true)
	if err != nil {
		t.Fatalf("output copy: %v", err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "PRETEND-JPEG-BYTES" {
		t.Fatalf("read %q", b)
	}
	f, err = c.OpenDownloadedMedia(cachePath, false)
	if err != nil {
		t.Fatalf("cache file: %v", err)
	}
	f.Close()

	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(mediaRoot, "inside-link.jpg")
	if err := os.Symlink(out, inside); err != nil {
		t.Fatal(err)
	}
	escaping := filepath.Join(mediaRoot, "escaping-link.jpg")
	if err := os.Symlink(secret, escaping); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{inside, escaping, secret} {
		if f, err := c.OpenDownloadedMedia(p, true); err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			t.Fatalf("OpenDownloadedMedia(%q) read %q", p, b)
		}
	}
	if f, err := c.OpenDownloadedMedia(cachePath, true); err == nil {
		f.Close()
		t.Fatal("cache path accepted as an output_path read")
	}
}
