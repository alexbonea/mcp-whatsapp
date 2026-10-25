package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The matrix of root configurations serve accepts and refuses. Paths are
// synthetic, under a temp "home" so the real home is never involved.
func TestResolveMediaRoots(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	state := filepath.Join(home, ".local", "state", "whatsapp-mcp")
	store := filepath.Join(state, "store")
	inbound := filepath.Join(home, "inbox", "attachments", "whatsapp")
	for _, d := range []string{store, inbound} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)

	t.Run("no variables: legacy single root under the store", func(t *testing.T) {
		r, err := resolveMediaRoots(store, "", "")
		if err != nil || r.inbound != filepath.Join(store, "uploads") || r.outbound != "" {
			t.Fatalf("roots = %+v, %v", r, err)
		}
		if _, err := os.Stat(r.inbound); err != nil {
			t.Fatalf("default media root not created: %v", err)
		}
	})
	t.Run("media root only: legacy, sends read the media root", func(t *testing.T) {
		r, err := resolveMediaRoots(store, inbound, "")
		if err != nil || r.inbound != inbound || r.outbound != "" {
			t.Fatalf("roots = %+v, %v", r, err)
		}
	})
	t.Run("both: separate roots, outbound created 0700", func(t *testing.T) {
		out := filepath.Join(state, "outbound")
		r, err := resolveMediaRoots(store, inbound, out)
		if err != nil || r.inbound != inbound || r.outbound != out {
			t.Fatalf("roots = %+v, %v", r, err)
		}
		info, err := os.Stat(out)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("outbound root %v %v", info, err)
		}
	})
	for name, out := range map[string]string{
		"relative":                  "outbound",
		"home":                      home,
		"state dir (store + token)": state,
		"store":                     store,
		"the media root":            inbound,
		"inside the media root":     filepath.Join(inbound, "out"),
		"the inbox above it":        filepath.Join(home, "inbox"),
		"system temp":               os.TempDir(),
		"/tmp":                      "/tmp",
		"/":                         "/",
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			if r, err := resolveMediaRoots(store, inbound, out); err == nil {
				t.Fatalf("accepted %q: %+v", out, r)
			}
		})
	}
}
