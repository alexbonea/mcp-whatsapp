package outbound

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeTrash records what was trashed and moves it into a scratch "Trash"
// directory, the way /usr/bin/trash moves it to ~/.Trash.
type fakeTrash struct {
	dir   string
	mu    sync.Mutex
	moved []string
	fail  error
}

func (f *fakeTrash) trash(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.moved = append(f.moved, p)
	return os.Rename(p, filepath.Join(f.dir, fmt.Sprintf("%d-%s", len(f.moved), filepath.Base(p))))
}

type fixture struct {
	t     *testing.T
	base  string
	root  string
	docs  string
	trash *fakeTrash
	now   time.Time
	h     *Helper
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t:     t,
		base:  base,
		root:  filepath.Join(base, "outbound"),
		docs:  filepath.Join(base, "bhq", "node"),
		trash: &fakeTrash{dir: filepath.Join(base, "Trash")},
		now:   time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC),
	}
	for _, d := range []string{f.root, f.docs, f.trash.dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.h = &Helper{Root: f.root, Trash: f.trash.trash, Now: func() time.Time { return f.now }}
	return f
}

func (f *fixture) doc(name, content string) string {
	f.t.Helper()
	p := filepath.Join(f.docs, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) opDirs() []string {
	f.t.Helper()
	entries, err := os.ReadDir(f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestStage_CopiesOneIndependentVerifiedFile(t *testing.T) {
	f := newFixture(t)
	const name = "Act constitutiv Brăila – rev 2 (semnat).pdf"
	src := f.doc(name, "%PDF-authorised")

	res, err := f.h.Stage(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != name || filepath.Base(res.Path) != name {
		t.Fatalf("name not preserved: %+v", res)
	}
	if res.SHA256 != sum("%PDF-authorised") || res.Size != int64(len("%PDF-authorised")) {
		t.Fatalf("digest/size wrong: %+v", res)
	}
	if !opDirPattern.MatchString(res.OpID) || filepath.Dir(res.OpDir) != f.root || filepath.Dir(res.Path) != res.OpDir {
		t.Fatalf("operation layout wrong: %+v", res)
	}
	dirInfo, _ := os.Stat(res.OpDir)
	fileInfo, _ := os.Lstat(res.Path)
	if dirInfo.Mode().Perm() != 0o700 || fileInfo.Mode().Perm() != 0o600 || !fileInfo.Mode().IsRegular() {
		t.Fatalf("modes: dir %v file %v", dirInfo.Mode(), fileInfo.Mode())
	}
	srcInfo, _ := os.Stat(src)
	if os.SameFile(srcInfo, fileInfo) || fileInfo.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("staged copy shares the source inode")
	}
	// Later edits to the source never reach the staged copy.
	if err := os.WriteFile(src, []byte("%PDF-edited-later"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(res.Path); string(b) != "%PDF-authorised" {
		t.Fatalf("staged copy changed with the source: %q", b)
	}
}

// Documents in entities can sit behind a symlink into a cloud library.
func TestStage_FollowsLegitimateSourceSymlink(t *testing.T) {
	f := newFixture(t)
	library := filepath.Join(f.base, "OneDrive", "FTV")
	if err := os.MkdirAll(library, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(library, "Contract.pdf"), []byte("cloud"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub := filepath.Join(f.base, "entities", "ftv")
	if err := os.MkdirAll(hub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(library, filepath.Join(hub, "library")); err != nil {
		t.Fatal(err)
	}
	res, err := f.h.Stage(filepath.Join(hub, "library", "Contract.pdf"), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.SourceReal != filepath.Join(library, "Contract.pdf") || res.Name != "Contract.pdf" {
		t.Fatalf("source resolution: %+v", res)
	}
}

func TestStage_Refusals(t *testing.T) {
	f := newFixture(t)
	fifo := filepath.Join(f.docs, "pipe.pdf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := f.h.Stage(f.doc("a.pdf", "a"), "")
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.opDirs())
	cases := map[string]string{
		"directory":        f.docs,
		"fifo":             fifo,
		"missing":          filepath.Join(f.docs, "missing.pdf"),
		"already staged":   staged.Path,
		"empty":            "",
		"outbound root":    f.root,
		"root of the disk": "/",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { _, err := f.h.Stage(src, ""); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("staged %q", src)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stage blocked")
			}
		})
	}
	if got := len(f.opDirs()); got != before {
		t.Fatalf("refusals left %d new entries in the root", got-before)
	}
}

func TestStage_ExpectedDigestSelectsTheAuthorisedVersion(t *testing.T) {
	f := newFixture(t)
	src := f.doc("offer.pdf", "v1")
	if _, err := f.h.Stage(src, strings.ToUpper(sum("v1"))); err != nil {
		t.Fatalf("matching digest refused: %v", err)
	}
	if err := os.WriteFile(src, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	n := len(f.opDirs())
	_, err := f.h.Stage(src, sum("v1"))
	if err == nil || !strings.Contains(err.Error(), "authorised version") {
		t.Fatalf("new version staged under the old digest: %v", err)
	}
	if len(f.opDirs()) != n {
		t.Fatal("refused stage created an operation directory")
	}
	if _, err := f.h.Stage(src, "not-hex"); err == nil {
		t.Fatal("malformed digest accepted")
	}
}

// Identical names and identical content never collide or overwrite.
func TestStage_ConcurrentSameNameAndContent(t *testing.T) {
	f := newFixture(t)
	a := f.doc("scan.pdf", "same-bytes")
	otherDir := filepath.Join(f.base, "personal")
	if err := os.MkdirAll(otherDir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(otherDir, "scan.pdf")
	if err := os.WriteFile(b, []byte("same-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]*StageResult, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src := a
			if i%2 == 1 {
				src = b
			}
			results[i], errs[i] = f.h.Stage(src, "")
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i, r := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if seen[r.OpDir] {
			t.Fatalf("operation directory reused: %s", r.OpDir)
		}
		seen[r.OpDir] = true
		if got, _ := os.ReadFile(r.Path); string(got) != "same-bytes" || r.SHA256 != sum("same-bytes") {
			t.Fatalf("copy %d wrong", i)
		}
	}
}

func TestStage_OperationIDCollisionRetries(t *testing.T) {
	f := newFixture(t)
	f.h.Rand = bytes.NewReader(append(bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{9}, 8)...))
	first, err := f.h.Stage(f.doc("a.pdf", "first"), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.h.Stage(f.doc("a.pdf", "second"), "")
	if err != nil {
		t.Fatal(err)
	}
	if first.OpDir == second.OpDir {
		t.Fatal("collision not retried")
	}
	if b, _ := os.ReadFile(first.Path); string(b) != "first" {
		t.Fatalf("first copy overwritten: %q", b)
	}
}

func TestStage_SourceChangedDuringCopyIsDiscarded(t *testing.T) {
	f := newFixture(t)
	src := f.doc("draft.pdf", "original")
	testHookAfterCopy = func() {
		if err := os.WriteFile(src, []byte("rewritten meanwhile"), 0o644); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookAfterCopy = nil })
	_, err := f.h.Stage(src, "")
	if err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("want changed-while-copying error, got %v", err)
	}
	if len(f.opDirs()) != 0 || len(f.trash.moved) != 1 {
		t.Fatalf("partial operation not moved to the Trash: root %v trashed %v", f.opDirs(), f.trash.moved)
	}
}

func TestHelper_RootChecks(t *testing.T) {
	f := newFixture(t)
	src := f.doc("a.pdf", "a")
	open := filepath.Join(f.base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(f.base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]string{
		"unset": "", "relative": "outbound", "missing": filepath.Join(f.base, "nope"),
		"group readable": open, "a file": file,
	} {
		t.Run(name, func(t *testing.T) {
			h := &Helper{Root: root, Trash: f.trash.trash}
			if _, err := h.Stage(src, ""); err == nil {
				t.Fatalf("root %q accepted", root)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(f.base, "nope")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("helper created a missing root")
	}
}

func TestCleanup_MovesOnlyOperationDirectories(t *testing.T) {
	f := newFixture(t)
	res, err := f.h.Stage(f.doc("a.pdf", "a"), "")
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(f.root, "dropped-by-hand.pdf")
	if err := os.WriteFile(foreign, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"root": f.root, "foreign file": foreign, "outside": f.doc("b.pdf", "b"), "missing": filepath.Join(f.root, "x"),
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			if _, err := f.h.Cleanup(target); err == nil {
				t.Fatalf("cleaned %q", target)
			}
		})
	}
	if len(f.trash.moved) != 0 {
		t.Fatalf("refused cleanups trashed %v", f.trash.moved)
	}
	got, err := f.h.Cleanup(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got.OpDir != res.OpDir || len(f.trash.moved) != 1 || f.trash.moved[0] != res.OpDir {
		t.Fatalf("cleanup moved %v, want %s", f.trash.moved, res.OpDir)
	}
	if _, err := os.Stat(res.OpDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("operation directory still present")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign file touched")
	}
}

// The daemon's shared lock marks a send in progress; cleanup must refuse
// and leave everything in place until the send releases it.
func TestCleanup_RefusesWhileSendHoldsTheFile(t *testing.T) {
	f := newFixture(t)
	res, err := f.h.Stage(f.doc("a.pdf", "a"), "")
	if err != nil {
		t.Fatal(err)
	}
	daemon, err := os.Open(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := LockInFlight(daemon); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Cleanup(res.OpDir); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	if len(f.trash.moved) != 0 {
		t.Fatal("busy operation was trashed")
	}
	// A second send of the same file shares the lock.
	second, _ := os.Open(res.Path)
	if err := LockInFlight(second); err != nil {
		t.Fatalf("concurrent sends must not block each other: %v", err)
	}
	second.Close()
	daemon.Close()
	if _, err := f.h.Cleanup(res.OpDir); err != nil {
		t.Fatalf("cleanup after the send returned: %v", err)
	}
}

// A daemon that dies mid-send releases its lock with its descriptors, so
// the operation becomes an ordinary orphan.
func TestCleanup_LockReleasedWhenHolderProcessDies(t *testing.T) {
	f := newFixture(t)
	res, err := f.h.Stage(f.doc("a.pdf", "a"), "")
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(f.base, "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcessHoldsLock$")
	cmd.Env = append(os.Environ(), "OUTBOUND_HOLD_LOCK="+res.Path, "OUTBOUND_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process did not take the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := f.h.Cleanup(res.OpDir); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy while the process holds the lock, got %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = cmd.Process.Wait()
	if _, err := f.h.Cleanup(res.OpDir); err != nil {
		t.Fatalf("cleanup after the holder died: %v", err)
	}
}

func TestHelperProcessHoldsLock(t *testing.T) {
	path := os.Getenv("OUTBOUND_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process for TestCleanup_LockReleasedWhenHolderProcessDies")
	}
	fh, err := os.Open(path)
	if err != nil {
		os.Exit(2)
	}
	if err := LockInFlight(fh); err != nil {
		os.Exit(3)
	}
	if err := os.WriteFile(os.Getenv("OUTBOUND_READY"), nil, 0o600); err != nil {
		os.Exit(4)
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestCleanup_TrashFailureKeepsTheCopy(t *testing.T) {
	f := newFixture(t)
	res, err := f.h.Stage(f.doc("a.pdf", "a"), "")
	if err != nil {
		t.Fatal(err)
	}
	f.trash.fail = errors.New("Finder unavailable")
	_, err = f.h.Cleanup(res.OpDir)
	if err == nil || !strings.Contains(err.Error(), "still there") {
		t.Fatalf("want explicit failure, got %v", err)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatal("copy vanished although the Trash failed")
	}
}

// Orphans become eligible after MinOrphanAge, only when no send holds
// them; younger operations, held operations and foreign entries stay.
func TestSweep_RecoversOnlyInactiveOldOperations(t *testing.T) {
	f := newFixture(t)
	old, err := f.h.Stage(f.doc("old.pdf", "old"), "")
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.h.Stage(f.doc("held.pdf", "held"), "")
	if err != nil {
		t.Fatal(err)
	}
	// An interrupted stage: directory created, copy never completed.
	partial := filepath.Join(f.root, f.now.Format(opTimeLayout)+"-00000000000000aa")
	if err := os.Mkdir(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "half.pdf"), []byte("ha"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(f.root, "notes")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, _ := os.Open(held.Path)
	if err := LockInFlight(lock); err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	f.now = f.now.Add(23 * time.Hour)
	young, err := f.h.Stage(f.doc("young.pdf", "young"), "")
	if err != nil {
		t.Fatal(err)
	}
	if young.Recovered != nil {
		t.Fatalf("recovered before 24h: %+v", young.Recovered)
	}

	f.now = f.now.Add(2 * time.Hour)
	r, err := f.h.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Recovered) != 2 || len(r.Active) != 1 || r.Active[0] != held.OpID || r.Kept != 1 || len(r.Foreign) != 1 {
		t.Fatalf("sweep = %+v", r)
	}
	for _, gone := range []string{old.OpDir, partial} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s not recovered", gone)
		}
	}
	for _, kept := range []string{held.Path, young.Path, foreign} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s removed: %v", kept, err)
		}
	}
}

func TestVerify(t *testing.T) {
	f := newFixture(t)
	res, err := f.h.Stage(f.doc("a.pdf", "abc"), "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.h.Verify(res.Path, res.SHA256)
	if err != nil || !v.Match || v.Size != 3 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	if v, err := f.h.Verify(res.Path, sum("other")); err != nil || v.Match {
		t.Fatalf("mismatch reported as %+v, %v", v, err)
	}
	if _, err := f.h.Verify(f.doc("b.pdf", "b"), sum("b")); err == nil {
		t.Fatal("verify read a file outside the root")
	}
	if _, err := f.h.Verify(res.Path, ""); err == nil {
		t.Fatal("verify without a digest accepted")
	}
}

// After a rate-limit refusal the copy is cleaned up; the retry stages the
// same version again, insisting on the digest recorded the first time.
func TestRestageAfterRefusal(t *testing.T) {
	f := newFixture(t)
	src := f.doc("invoice.pdf", "authorised")
	first, err := f.h.Stage(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Cleanup(first.OpDir); err != nil {
		t.Fatal(err)
	}
	again, err := f.h.Stage(src, first.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if again.OpDir == first.OpDir || again.SHA256 != first.SHA256 {
		t.Fatalf("retry = %+v", again)
	}
	b, _ := io.ReadAll(must(os.Open(again.Path)))
	if string(b) != "authorised" {
		t.Fatalf("retry content %q", b)
	}
}

func must(f *os.File, err error) *os.File {
	if err != nil {
		panic(err)
	}
	return f
}
