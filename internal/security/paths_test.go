package security

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// layout builds a synthetic host under t.TempDir(): an allowed root plus
// stand-ins for the places a media path must never reach. No real home,
// archive, store or token is touched.
type layout struct {
	root, archive, home, store, token string
}

func newLayout(t *testing.T) layout {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l := layout{
		root:    filepath.Join(base, "state", "whatsapp-mcp", "outbound"),
		archive: filepath.Join(base, "_archives", "contracts"),
		home:    filepath.Join(base, "home"),
		store:   filepath.Join(base, "state", "whatsapp-mcp", "store"),
		token:   filepath.Join(base, "state", "whatsapp-mcp", "token"),
	}
	for _, d := range []string{l.root, l.archive, l.home, l.store} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(l.archive, "contract.pdf"), "ARCHIVED-CONTRACT")
	writeTestFile(t, filepath.Join(l.home, "id_ed25519"), "PRIVATE-KEY")
	writeTestFile(t, filepath.Join(l.store, "whatsapp.db"), "SESSION-DB")
	writeTestFile(t, l.token, "BEARER-TOKEN")
	return l
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readAllClose(t *testing.T, f *os.File) string {
	t.Helper()
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOpenRegular_InsideRoot(t *testing.T) {
	l := newLayout(t)
	file := filepath.Join(l.root, "Contract Brăila v2 (final).pdf")
	writeTestFile(t, file, "STAGED")
	f, got, err := OpenRegular(file, l.root, OpenOptions{Field: "media_path"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != file {
		t.Fatalf("resolved %q, want %q", got, file)
	}
	if s := readAllClose(t, f); s != "STAGED" {
		t.Fatalf("read %q", s)
	}
}

// Every protected stand-in is outside the root and must be refused with an
// error that names the root, whether addressed directly, through a symlink
// planted in the root, or through `..`.
func TestOpenRegular_ProtectedPathsOutsideRoot(t *testing.T) {
	l := newLayout(t)
	targets := map[string]string{
		"archive": filepath.Join(l.archive, "contract.pdf"),
		"home":    filepath.Join(l.home, "id_ed25519"),
		"store":   filepath.Join(l.store, "whatsapp.db"),
		"token":   l.token,
	}
	for name, target := range targets {
		t.Run(name+"/direct", func(t *testing.T) {
			_, _, err := OpenRegular(target, l.root, OpenOptions{Field: "media_path"})
			if !errors.Is(err, ErrOutsideRoot) || !strings.Contains(err.Error(), "allowed root") {
				t.Fatalf("want ErrOutsideRoot mentioning allowed root, got %v", err)
			}
		})
		t.Run(name+"/symlink", func(t *testing.T) {
			link := filepath.Join(l.root, name+"-link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenRegular(link, l.root, OpenOptions{}); !errors.Is(err, ErrOutsideRoot) {
				t.Fatalf("symlink escape accepted: %v", err)
			}
		})
		t.Run(name+"/traversal", func(t *testing.T) {
			rel, err := filepath.Rel(l.root, target)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenRegular(l.root+string(filepath.Separator)+rel, l.root, OpenOptions{}); !errors.Is(err, ErrOutsideRoot) {
				t.Fatalf("traversal accepted: %v", err)
			}
		})
	}
}

func TestOpenRegular_PrefixSiblingRejected(t *testing.T) {
	l := newLayout(t)
	sibling := l.root + "-other"
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sibling, "x.pdf")
	writeTestFile(t, file, "x")
	if _, _, err := OpenRegular(file, l.root, OpenOptions{}); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("sibling sharing the root's prefix accepted: %v", err)
	}
}

func TestOpenRegular_HintNamesRemedy(t *testing.T) {
	l := newLayout(t)
	_, _, err := OpenRegular(l.token, l.root, OpenOptions{Field: "media_path"})
	if err == nil || !strings.Contains(err.Error(), "WHATSAPP_MCP_MEDIA_ROOT") {
		t.Fatalf("legacy hint missing: %v", err)
	}
	_, _, err = OpenRegular(l.token, l.root, OpenOptions{Field: "media_path", Hint: "stage a copy"})
	if err == nil || !strings.Contains(err.Error(), "stage a copy") || strings.Contains(err.Error(), "WHATSAPP_MCP_MEDIA_ROOT") {
		t.Fatalf("custom hint not used: %v", err)
	}
}

func TestOpenRegular_SymlinkInsideRoot(t *testing.T) {
	l := newLayout(t)
	real := filepath.Join(l.root, "real.txt")
	writeTestFile(t, real, "y")
	link := filepath.Join(l.root, "alias")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	f, got, err := OpenRegular(link, l.root, OpenOptions{})
	if err != nil {
		t.Fatalf("symlink inside root should pass, got %v", err)
	}
	f.Close()
	if got != real {
		t.Fatalf("want resolved path %q, got %q", real, got)
	}
}

func TestOpenRegular_EmptyAndMissing(t *testing.T) {
	l := newLayout(t)
	if _, _, err := OpenRegular("", l.root, OpenOptions{Field: "media_path"}); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, _, err := OpenRegular(filepath.Join(l.root, "nope.txt"), l.root, OpenOptions{}); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestOpenRegular_RelativePath(t *testing.T) {
	l := newLayout(t)
	writeTestFile(t, filepath.Join(l.root, "rel.txt"), "rel")
	t.Chdir(l.root)
	if _, _, err := OpenRegular("rel.txt", l.root, OpenOptions{RequireAbs: true}); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("strict mode accepted a relative path: %v", err)
	}
	f, _, err := OpenRegular("rel.txt", l.root, OpenOptions{})
	if err != nil {
		t.Fatalf("legacy mode should resolve relative paths against the cwd: %v", err)
	}
	f.Close()
}

// Directories (the root itself included), FIFOs and devices are refused
// on the opened descriptor; opening a FIFO must not block.
func TestOpenRegular_RejectsNonRegularFiles(t *testing.T) {
	l := newLayout(t)
	sub := filepath.Join(l.root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(l.root, "pipe.pdf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"root": l.root, "subdir": sub, "fifo": fifo}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				f, _, err := OpenRegular(p, l.root, OpenOptions{})
				if f != nil {
					f.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("want not-a-regular-file error, got %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("OpenRegular blocked")
			}
		})
	}
	t.Run("device via symlink", func(t *testing.T) {
		link := filepath.Join(l.root, "null.pdf")
		if err := os.Symlink("/dev/null", link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := OpenRegular(link, l.root, OpenOptions{}); err == nil {
			t.Fatal("device reached through a symlink accepted")
		}
	})
}

// A hard link inside the root to a protected file passes every path check
// (it is a regular file inside the root). The dedicated outbound root
// refuses it; the legacy root keeps accepting it because download_media
// used to materialise output_path as a hard link to the cache.
func TestOpenRegular_HardLinks(t *testing.T) {
	l := newLayout(t)
	link := filepath.Join(l.root, "harmless.pdf")
	if err := os.Link(l.token, link); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if _, _, err := OpenRegular(link, l.root, OpenOptions{SingleLink: true}); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("strict mode accepted a hard link: %v", err)
	}
	f, _, err := OpenRegular(link, l.root, OpenOptions{})
	if err != nil {
		t.Fatalf("legacy mode should keep accepting hard links: %v", err)
	}
	f.Close()
}

// Regression for validate-then-open: the old ValidateMediaPath resolved
// the path, then os.ReadFile reopened it by name, so replacing a parent
// directory with a symlink in between made the daemon read (and upload) a
// file outside the root. The confined open refuses instead.
func TestOpenRegular_ParentSwappedAfterResolution(t *testing.T) {
	l := newLayout(t)
	opDir := filepath.Join(l.root, "op")
	if err := os.Mkdir(opDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(opDir, "contract.pdf"), "STAGED")
	testHookBeforeOpen = func() {
		if err := os.Rename(opDir, opDir+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(l.archive, opDir); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { testHookBeforeOpen = nil })

	f, _, err := OpenRegular(filepath.Join(opDir, "contract.pdf"), l.root, OpenOptions{})
	if err == nil {
		content := readAllClose(t, f)
		t.Fatalf("swap was followed outside the root; read %q", content)
	}
}

func TestOpenRegular_FileSwappedForEscapingSymlink(t *testing.T) {
	l := newLayout(t)
	file := filepath.Join(l.root, "contract.pdf")
	writeTestFile(t, file, "STAGED")
	testHookBeforeOpen = func() {
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(l.token, file); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { testHookBeforeOpen = nil })
	f, _, err := OpenRegular(file, l.root, OpenOptions{})
	if err == nil {
		t.Fatalf("followed a swapped-in symlink outside the root; read %q", readAllClose(t, f))
	}
}

func TestResolveOutputPath_InsideAndNested(t *testing.T) {
	l := newLayout(t)
	got, err := ResolveOutputPath(filepath.Join(l.root, "new.jpg"), l.root)
	if err != nil || got.Path != filepath.Join(l.root, "new.jpg") || got.Rel != "new.jpg" {
		t.Fatalf("got %+v, %v", got, err)
	}
	nested := filepath.Join(l.root, "2026-10-25-x")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	tgt, err := ResolveOutputPath(filepath.Join(nested, "x.jpg"), l.root)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Rel != filepath.Join("2026-10-25-x", "x.jpg") || tgt.Root != l.root {
		t.Fatalf("target = %+v", tgt)
	}
}

func TestResolveOutputPath_Rejections(t *testing.T) {
	l := newLayout(t)
	link := filepath.Join(l.root, "escape")
	if err := os.Symlink(l.archive, link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty":                "",
		"missing parent":       filepath.Join(l.root, "does-not-exist-dir", "x.jpg"),
		"outside":              filepath.Join(l.home, "x.jpg"),
		"traversal":            filepath.Join(l.root, "..", "store", "x.jpg"),
		"symlinked parent out": filepath.Join(link, "x.jpg"),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ResolveOutputPath(p, l.root); err == nil {
				t.Fatalf("accepted %q", p)
			}
		})
	}
}

func TestResolveOutputPath_SymlinkParentInsideRoot(t *testing.T) {
	l := newLayout(t)
	real := filepath.Join(l.root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(l.root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveOutputPath(filepath.Join(l.root, "alias", "x.jpg"), l.root); err != nil {
		t.Fatalf("symlinked parent inside root should pass, got %v", err)
	}
}

// A symlink at the final component passes path validation (it is the
// caller's chosen name) but every confined operation refuses to follow it.
func TestTarget_FinalSymlinkIsNeverFollowed(t *testing.T) {
	l := newLayout(t)
	dest := filepath.Join(l.root, "photo.jpg")
	if err := os.Symlink(l.token, dest); err != nil {
		t.Fatal(err)
	}
	tgt, err := ResolveOutputPath(dest, l.root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := tgt.Lstat()
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat should report the symlink itself: %v %v", info, err)
	}
	if f, err := tgt.CreateExclusive(); !errors.Is(err, fs.ErrExist) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("CreateExclusive over a symlink: %v", err)
	}
	if f, err := tgt.OpenRegular(); err == nil {
		t.Fatalf("OpenRegular followed the symlink; read %q", readAllClose(t, f))
	}
	if b, _ := os.ReadFile(l.token); string(b) != "BEARER-TOKEN" {
		t.Fatal("token stand-in modified")
	}
}

func TestTarget_CreateExclusiveAndOpen(t *testing.T) {
	l := newLayout(t)
	tgt, err := ResolveOutputPath(filepath.Join(l.root, "a.jpg"), l.root)
	if err != nil {
		t.Fatal(err)
	}
	f, err := tgt.CreateExclusive()
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("IMG")
	f.Close()
	info, _ := os.Stat(tgt.Path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	if _, err := tgt.CreateExclusive(); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second create should fail with ErrExist: %v", err)
	}
	r, err := tgt.OpenRegular()
	if err != nil {
		t.Fatal(err)
	}
	if s := readAllClose(t, r); s != "IMG" {
		t.Fatalf("read %q", s)
	}
}

func TestPrepareDedicatedRoot(t *testing.T) {
	l := newLayout(t)
	base := filepath.Dir(filepath.Dir(l.store)) // .../state
	inbound := filepath.Join(filepath.Dir(base), "inbox", "attachments", "whatsapp")
	if err := os.MkdirAll(inbound, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := DedicatedRootPolicy{
		Protected: []string{l.home, l.store, filepath.Join(filepath.Dir(base), "tmp")},
		Disjoint:  []string{inbound},
	}

	t.Run("creates missing root 0700", func(t *testing.T) {
		root := filepath.Join(base, "whatsapp-mcp", "fresh-outbound")
		got, err := PrepareDedicatedRoot("ROOT", root, policy)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(got)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("root %v mode %v err %v", got, info.Mode(), err)
		}
	})
	t.Run("accepts sibling of the store", func(t *testing.T) {
		if _, err := PrepareDedicatedRoot("ROOT", l.root, policy); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("resolves a symlinked root", func(t *testing.T) {
		link := filepath.Join(base, "outbound-link")
		if err := os.Symlink(l.root, link); err != nil {
			t.Fatal(err)
		}
		got, err := PrepareDedicatedRoot("ROOT", link, policy)
		if err != nil || got != l.root {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	refusals := map[string]string{
		"relative":                "relative/outbound",
		"filesystem root":         "/",
		"home itself":             l.home,
		"parent of home":          filepath.Dir(l.home),
		"store itself":            l.store,
		"parent of store + token": filepath.Dir(l.store),
		"temp":                    filepath.Join(filepath.Dir(base), "tmp"),
		"inbound itself":          inbound,
		"inside inbound":          filepath.Join(inbound, "outbound"),
		"parent of inbound":       filepath.Dir(inbound),
	}
	for name, root := range refusals {
		t.Run("refuses "+name, func(t *testing.T) {
			if _, err := PrepareDedicatedRoot("ROOT", root, policy); err == nil {
				t.Fatalf("accepted %q", root)
			}
		})
	}
	t.Run("refuses a symlink to home", func(t *testing.T) {
		link := filepath.Join(base, "sneaky")
		if err := os.Symlink(l.home, link); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareDedicatedRoot("ROOT", link, policy); err == nil {
			t.Fatal("accepted a symlink resolving to home")
		}
	})
	t.Run("refuses group-accessible root", func(t *testing.T) {
		open := filepath.Join(base, "open-outbound")
		if err := os.Mkdir(open, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := PrepareDedicatedRoot("ROOT", open, policy)
		if err == nil || !strings.Contains(err.Error(), "chmod 700") {
			t.Fatalf("want chmod hint, got %v", err)
		}
	})
	t.Run("refuses a file", func(t *testing.T) {
		file := filepath.Join(base, "not-a-dir")
		writeTestFile(t, file, "x")
		if _, err := PrepareDedicatedRoot("ROOT", file, policy); err == nil {
			t.Fatal("accepted a regular file as root")
		}
	})
}

func TestWithin(t *testing.T) {
	l := newLayout(t)
	if !Within(filepath.Join(l.root, "a", "b"), l.root) || !Within(l.root, l.root) {
		t.Fatal("paths under the root not recognised")
	}
	if Within(l.root+"-other", l.root) || Within(l.home, l.root) || Within("", l.root) {
		t.Fatal("outside path reported within")
	}
}

func TestSafeFilename(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // "" means must match the fallback pattern
	}{
		{"plain", "photo.jpg", "photo.jpg"},
		{"path strips to base", "a/b/c.txt", "c.txt"},
		{"traversal strips to leaf", "../etc/passwd", "passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeFilename(tc.in)
			if got != tc.want {
				t.Fatalf("SafeFilename(%q): want %q, got %q", tc.in, tc.want, got)
			}
		})
	}

	fallbacks := []string{"", ".", "..", "/"}
	for _, in := range fallbacks {
		t.Run("fallback/"+in, func(t *testing.T) {
			got := SafeFilename(in)
			if !strings.HasPrefix(got, "document_") {
				t.Fatalf("SafeFilename(%q) should fall back to document_*, got %q", in, got)
			}
		})
	}

	t.Run("null byte falls back", func(t *testing.T) {
		got := SafeFilename("evil\x00name.txt")
		if !strings.HasPrefix(got, "document_") {
			t.Fatalf("null-byte name should fall back, got %q", got)
		}
	})
}
