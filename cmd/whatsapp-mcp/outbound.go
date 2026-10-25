package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/sealjay/mcp-whatsapp/internal/outbound"
)

const outboundUsage = `whatsapp-mcp outbound: stage documents for send_file in the outbound root.

Usage:
  whatsapp-mcp outbound stage   [-root DIR] [-sha256 HEX] SOURCE
  whatsapp-mcp outbound verify  [-root DIR] -sha256 HEX STAGED_PATH
  whatsapp-mcp outbound cleanup [-root DIR] OP_DIR_OR_STAGED_PATH
  whatsapp-mcp outbound sweep   [-root DIR]

stage    copies one regular file into a new private operation directory,
         keeping its name, and prints {op_id, op_dir, path, name, size,
         sha256, ...}. With -sha256 the source must match that digest.
         Operation directories older than 24h that no send holds are moved
         to the Trash first.
verify   re-hashes a staged copy; exit 0 only when it matches -sha256.
cleanup  moves the operation directory to the Trash once the send has a
         definite outcome; exit 3, touching nothing, while a send holds it.
sweep    the orphan recovery stage runs, on its own.

The root defaults to $WHATSAPP_MCP_OUTBOUND_ROOT and must exist with mode
0700; the daemon creates it at startup. This command never sends anything
and reads no credentials or databases.

Flags:
  -root DIR     outbound root (default $WHATSAPP_MCP_OUTBOUND_ROOT)
  -sha256 HEX   expected SHA-256 of the source (stage) or copy (verify)
  -trash CMD    command that moves a path to the Trash (default trash)

Exit codes: 0 done, 1 failed, 2 usage, 3 a send still holds the files.
`

// exitBusy tells the caller that a send in progress holds the files and
// nothing was cleaned up.
const exitBusy = 3

func runOutbound(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, outboundUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("outbound "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, outboundUsage) }
	root := fs.String("root", os.Getenv("WHATSAPP_MCP_OUTBOUND_ROOT"), "outbound root")
	trashCmd := fs.String("trash", "trash", "command that moves a path to the Trash")
	var sha string
	if sub == "stage" || sub == "verify" {
		fs.StringVar(&sha, "sha256", "", "expected SHA-256")
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	h := &outbound.Helper{Root: *root, Trash: trashWith(*trashCmd)}

	wantArgs := 1
	if sub == "sweep" {
		wantArgs = 0
	}
	if fs.NArg() != wantArgs {
		fmt.Fprintf(stderr, "outbound %s: expected %d path argument(s), got %d\n\n%s", sub, wantArgs, fs.NArg(), outboundUsage)
		return 2
	}

	var (
		res any
		err error
	)
	switch sub {
	case "stage":
		res, err = h.Stage(fs.Arg(0), sha)
	case "verify":
		var v *outbound.VerifyResult
		v, err = h.Verify(fs.Arg(0), sha)
		if err == nil && !v.Match {
			printJSON(stdout, v)
			fmt.Fprintf(stderr, "outbound verify: %s has SHA-256 %s, expected %s\n", v.Path, v.SHA256, strings.ToLower(sha))
			return 1
		}
		res = v
	case "cleanup":
		res, err = h.Cleanup(fs.Arg(0))
	case "sweep":
		res, err = h.Sweep()
	default:
		fmt.Fprintf(stderr, "outbound: unknown command %q\n\n%s", sub, outboundUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "outbound %s: %v\n", sub, err)
		if errors.Is(err, outbound.ErrBusy) {
			return exitBusy
		}
		return 1
	}
	printJSON(stdout, res)
	return 0
}

func printJSON(w io.Writer, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(w, string(b))
}

// trashWith runs cmd with the path as its only argument (macOS ships
// /usr/bin/trash). Paths are absolute, so they cannot be read as options.
func trashWith(cmd string) func(string) error {
	return func(path string) error {
		out, err := exec.Command(cmd, path).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", cmd, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}
