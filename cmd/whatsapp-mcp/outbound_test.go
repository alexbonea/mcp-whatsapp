package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealjay/mcp-whatsapp/internal/outbound"
)

func TestRunOutbound_StageVerifyCleanup(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "outbound")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(base, "Împuternicire broker.pdf")
	if err := os.WriteFile(src, []byte("%PDF"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stand-in for /usr/bin/trash that moves the path aside.
	trashDir := filepath.Join(base, "Trash")
	if err := os.Mkdir(trashDir, 0o700); err != nil {
		t.Fatal(err)
	}
	trash := filepath.Join(base, "fake-trash")
	if err := os.WriteFile(trash, []byte("#!/bin/sh\nmv \"$1\" "+trashDir+"/\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := runOutbound(args, &out, &errOut)
		return code, out.String(), errOut.String()
	}

	code, out, errOut := run("stage", "-root", root, "-trash", trash, src)
	if code != 0 {
		t.Fatalf("stage exit %d: %s", code, errOut)
	}
	var staged outbound.StageResult
	if err := json.Unmarshal([]byte(out), &staged); err != nil {
		t.Fatalf("stage output is not JSON: %v\n%s", err, out)
	}
	if staged.Name != "Împuternicire broker.pdf" || staged.Size != 4 {
		t.Fatalf("staged = %+v", staged)
	}

	if code, _, _ := run("verify", "-root", root, "-sha256", staged.SHA256, staged.Path); code != 0 {
		t.Fatalf("verify of a matching copy exited %d", code)
	}
	if code, _, _ := run("verify", "-root", root, "-sha256", strings.Repeat("0", 64), staged.Path); code != 1 {
		t.Fatalf("verify of a mismatching digest exited %d", code)
	}

	held, err := os.Open(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbound.LockInFlight(held); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run("cleanup", "-root", root, "-trash", trash, staged.OpDir); code != exitBusy {
		t.Fatalf("cleanup during a send exited %d (%s), want %d", code, errOut, exitBusy)
	}
	held.Close()
	if code, _, errOut := run("cleanup", "-root", root, "-trash", trash, staged.OpDir); code != 0 {
		t.Fatalf("cleanup exited %d: %s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(trashDir, staged.OpID, staged.Name)); err != nil {
		t.Fatalf("operation not in the Trash: %v", err)
	}

	if code, _, _ := run("sweep", "-root", root, "-trash", trash); code != 0 {
		t.Fatalf("sweep exited %d", code)
	}
	for _, bad := range [][]string{{}, {"bogus"}, {"stage"}, {"cleanup", "a", "b"}} {
		if code, _, _ := run(bad...); code != 2 {
			t.Fatalf("%v exited %d, want 2", bad, code)
		}
	}
	if code, _, _ := run("stage", "-root", filepath.Join(base, "missing"), src); code != 1 {
		t.Fatalf("missing root exited %d, want 1", code)
	}
}
