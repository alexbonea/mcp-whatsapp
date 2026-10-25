//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type roots struct {
	inbound, outbound string
}

func newRoots(t *testing.T) roots {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := roots{
		inbound:  filepath.Join(base, "inbox", "attachments", "whatsapp"),
		outbound: filepath.Join(base, "state", "outbound"),
	}
	if err := os.MkdirAll(r.inbound, 0o700); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r roots) env() []string {
	return []string{"WHATSAPP_MCP_MEDIA_ROOT=" + r.inbound, "WHATSAPP_MCP_OUTBOUND_ROOT=" + r.outbound}
}

// With the override, a file the daemon itself would have received (in the
// inbound root) is refused before anything else happens.
func TestOutboundRoot_RefusesInboundFile(t *testing.T) {
	r := newRoots(t)
	h := newHarnessEnv(t, r.env()...)
	h.initializeMCP()
	received := filepath.Join(r.inbound, "scan.pdf")
	if err := os.WriteFile(received, []byte("%PDF"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := h.callTool("send_file", map[string]any{"recipient": "00000000", "media_path": received})
	if !res.IsError || !strings.Contains(res.Text, "allowed root") || !strings.Contains(res.Text, "inbound media root") {
		t.Fatalf("want refusal naming the inbound root, got %+v", res)
	}
	info, err := os.Stat(r.outbound)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("daemon did not create the outbound root 0700: %v %v", info, err)
	}
}

// The daemon creates the outbound root; the staging command of the same
// binary accepts it, stages a copy and moves it to the Trash afterwards.
// (A send is not attempted: an unpaired daemon would contact WhatsApp.)
func TestOutboundRoot_StageAndCleanupInDaemonRoot(t *testing.T) {
	r := newRoots(t)
	h := newHarnessEnv(t, r.env()...)
	h.initializeMCP()
	src := filepath.Join(t.TempDir(), "Procură broker.pdf")
	if err := os.WriteFile(src, []byte("%PDF-auth"), 0o600); err != nil {
		t.Fatal(err)
	}
	trashDir := t.TempDir()
	trash := filepath.Join(t.TempDir(), "fake-trash")
	if err := os.WriteFile(trash, []byte("#!/bin/sh\nmv \"$1\" "+trashDir+"/\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	stage := exec.Command(binary(t), "outbound", "stage", "-root", r.outbound, src)
	stage.Stdout, stage.Stderr = &out, os.Stderr
	if err := stage.Run(); err != nil {
		t.Fatalf("outbound stage: %v", err)
	}
	var staged struct {
		OpDir string `json:"op_dir"`
		Path  string `json:"path"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(out.Bytes(), &staged); err != nil {
		t.Fatalf("stage output: %v (%s)", err, out.String())
	}
	if filepath.Dir(staged.OpDir) != r.outbound || staged.Name != "Procură broker.pdf" {
		t.Fatalf("staged = %+v", staged)
	}
	cleanup := exec.Command(binary(t), "outbound", "cleanup", "-root", r.outbound, "-trash", trash, staged.OpDir)
	cleanup.Stdout, cleanup.Stderr = os.Stderr, os.Stderr
	if err := cleanup.Run(); err != nil {
		t.Fatalf("outbound cleanup: %v", err)
	}
	if _, err := os.Stat(staged.OpDir); !os.IsNotExist(err) {
		t.Fatalf("operation directory still present: %v", err)
	}
}

func TestServe_RefusesUnsafeOutboundRoot(t *testing.T) {
	r := newRoots(t)
	for name, out := range map[string]string{
		"same as media root": r.inbound,
		"relative":           "outbound",
		"inside media root":  filepath.Join(r.inbound, "out"),
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(binary(t), "-store", t.TempDir(), "serve", "-addr", "127.0.0.1:0")
			cmd.Env = append(os.Environ(), "WHATSAPP_MCP_MEDIA_ROOT="+r.inbound, "WHATSAPP_MCP_OUTBOUND_ROOT="+out)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 || !strings.Contains(stderr.String(), "refusing to start") {
				t.Fatalf("want exit 2 refusing to start, got %v: %s", err, stderr.String())
			}
		})
	}
}
