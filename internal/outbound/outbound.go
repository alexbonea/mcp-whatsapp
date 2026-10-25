// Package outbound implements the staging protocol for files the daemon
// sends from a dedicated outbound root (WHATSAPP_MCP_OUTBOUND_ROOT).
//
// An agent copies one authorised document into a fresh per-operation
// directory under the root (Stage) and passes the copy to send_file. The
// daemon holds a shared flock on the file it reads for as long as the send
// runs (LockInFlight); the lock lives with the descriptor, so it disappears
// when the send returns or the daemon dies. Once the outcome is known the
// agent moves the operation directory to the Trash (Cleanup), which refuses
// while a send still holds the lock. Operation directories left behind are
// recovered by a later Stage or Sweep once they are older than MinOrphanAge
// and no send holds them. Nothing records operations besides the directory
// names themselves.
package outbound

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/security"
)

// ErrBusy reports that another holder has the staged file locked: for the
// staging helper, a send in progress; for the daemon, a cleanup in progress.
var ErrBusy = errors.New("staged file is locked by another operation")

// DefaultMinOrphanAge is how old an operation directory must be before a
// later Stage or Sweep moves it to the Trash. It is an eligibility
// threshold, not a deletion deadline: nothing runs until the next use.
const DefaultMinOrphanAge = 24 * time.Hour

const opTimeLayout = "20060102T150405Z"

// opDirPattern matches the directories Stage creates:
// <UTC timestamp>-<16 hex digits>.
var opDirPattern = regexp.MustCompile(`^(\d{8}T\d{6}Z)-[0-9a-f]{16}$`)

// testHookAfterCopy runs between the copy and the source re-check.
var testHookAfterCopy func()

// LockInFlight takes the daemon's shared lock on a file it is about to
// send. Shared locks coexist, so two sends of one file do not block each
// other; Cleanup's exclusive lock does.
func LockInFlight(f *os.File) error {
	return flock(f, syscall.LOCK_SH)
}

func flock(f *os.File, how int) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := rc.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), how|syscall.LOCK_NB)
	}); err != nil {
		return err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		return ErrBusy
	}
	return lockErr
}

// Helper runs the staging commands against one outbound root.
type Helper struct {
	Root         string                  // outbound root; must exist, be owned by this user and be 0700
	Trash        func(path string) error // moves a path to the Trash; required for anything that cleans up
	MinOrphanAge time.Duration           // defaults to DefaultMinOrphanAge
	Now          func() time.Time        // defaults to time.Now
	Rand         io.Reader               // defaults to crypto/rand
}

// StageResult describes a staged copy. The agent keeps it in its session
// to send, verify and clean up; nothing else records it.
type StageResult struct {
	OpID       string       `json:"op_id"`
	OpDir      string       `json:"op_dir"`
	Path       string       `json:"path"` // pass as media_path
	Name       string       `json:"name"`
	Size       int64        `json:"size"`
	SHA256     string       `json:"sha256"`
	Source     string       `json:"source"`
	SourceReal string       `json:"source_real"`
	Recovered  *SweepResult `json:"recovered,omitempty"`
}

// SweepResult lists what a sweep found in the outbound root.
type SweepResult struct {
	Recovered []string `json:"recovered,omitempty"` // operation directories moved to the Trash
	Active    []string `json:"active,omitempty"`    // old enough, but a send still holds them
	Kept      int      `json:"kept"`                // younger than MinOrphanAge
	Foreign   []string `json:"foreign,omitempty"`   // entries Stage did not create; never touched
	Errors    []string `json:"errors,omitempty"`
}

// CleanupResult reports an operation directory moved to the Trash.
type CleanupResult struct {
	OpID    string `json:"op_id"`
	OpDir   string `json:"op_dir"`
	Trashed bool   `json:"trashed"`
}

// VerifyResult reports the size and digest of a staged copy.
type VerifyResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Match  bool   `json:"match"`
}

// Stage copies source into a new operation directory and verifies the copy.
//
// The source is resolved through symlinks (documents may live behind a
// link into a cloud library) and must be a single regular file. The copy
// keeps the source's file name, is created exclusively with mode 0600 in a
// directory of mode 0700, and is an independent file: no symlink, no hard
// link. The source is hashed before and during the copy and the copy is
// hashed again afterwards; any difference, or a source modified meanwhile,
// discards the operation. When wantSHA is set the source must match it, so
// a retry can insist on the exact version that was authorised.
func (h *Helper) Stage(source, wantSHA string) (*StageResult, error) {
	root, err := h.checkRoot()
	if err != nil {
		return nil, err
	}
	wantSHA, err = normaliseSHA(wantSHA)
	if err != nil {
		return nil, err
	}
	if source == "" {
		return nil, errors.New("source path is required")
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, fmt.Errorf("invalid source %q: %w", source, err)
	}
	abs = filepath.Clean(abs)
	name := filepath.Base(abs)
	if err := checkName(name); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("source %q not accessible: %w", abs, err)
	}
	if security.Within(real, root) {
		return nil, fmt.Errorf("source %q is already inside the outbound root; stage from the original document", real)
	}

	src, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	defer src.Close()
	before, err := src.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("source %q is not a regular file; stage copies one document at a time, never a directory", real)
	}
	sum, size, err := digest(io.NewSectionReader(src, 0, math.MaxInt64), io.Discard)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	if wantSHA != "" && sum != wantSHA {
		return nil, fmt.Errorf("source SHA-256 %s does not match the expected %s; this is not the authorised version", sum, wantSHA)
	}

	recovered := h.sweep(root)

	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open outbound root: %w", err)
	}
	defer r.Close()
	opID, err := h.makeOpDir(r)
	if err != nil {
		return nil, err
	}
	opDir := filepath.Join(root, opID)
	rel := filepath.Join(opID, name)
	fail := func(cause error) (*StageResult, error) {
		if terr := h.trash(opDir); terr != nil {
			return nil, fmt.Errorf("%w; moving the incomplete copy to the Trash also failed (%v), remove %s by hand", cause, terr, opDir)
		}
		return nil, cause
	}

	dst, err := r.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(fmt.Errorf("create staged copy: %w", err))
	}
	copySum, copySize, err := digest(io.NewSectionReader(src, 0, math.MaxInt64), dst)
	if err == nil {
		err = dst.Sync()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(fmt.Errorf("copy source: %w", err))
	}
	if testHookAfterCopy != nil {
		testHookAfterCopy()
	}
	after, err := src.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat source: %w", err))
	}
	still, err := os.Stat(real)
	changed := copySum != sum || copySize != size || after.Size() != before.Size() ||
		!after.ModTime().Equal(before.ModTime()) || err != nil || !os.SameFile(still, after)
	if changed {
		return fail(fmt.Errorf("source %q changed while it was being copied; nothing was staged", real))
	}

	staged, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fail(fmt.Errorf("reopen staged copy: %w", err))
	}
	info, err := staged.Stat()
	var stagedSum string
	var stagedSize int64
	if err == nil {
		stagedSum, stagedSize, err = digest(staged, io.Discard)
	}
	staged.Close()
	if err != nil {
		return fail(fmt.Errorf("verify staged copy: %w", err))
	}
	if !info.Mode().IsRegular() || security.LinkCount(info) != 1 || stagedSum != sum || stagedSize != size {
		return fail(fmt.Errorf("staged copy does not match the source (size %d vs %d, SHA-256 %s vs %s)", stagedSize, size, stagedSum, sum))
	}

	res := &StageResult{
		OpID:       opID,
		OpDir:      opDir,
		Path:       filepath.Join(opDir, name),
		Name:       name,
		Size:       size,
		SHA256:     sum,
		Source:     abs,
		SourceReal: real,
	}
	if recovered.notable() {
		res.Recovered = recovered
	}
	return res, nil
}

// Verify hashes a staged copy and compares it with wantSHA.
func (h *Helper) Verify(path, wantSHA string) (*VerifyResult, error) {
	root, err := h.checkRoot()
	if err != nil {
		return nil, err
	}
	wantSHA, err = normaliseSHA(wantSHA)
	if err != nil {
		return nil, err
	}
	if wantSHA == "" {
		return nil, errors.New("verify needs the expected SHA-256")
	}
	f, resolved, err := security.OpenRegular(path, root, security.OpenOptions{
		Field: "path", RequireAbs: true, SingleLink: true,
		Hint: "verify only reads staged copies",
	})
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sum, size, err := digest(f, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", resolved, err)
	}
	return &VerifyResult{Path: resolved, Size: size, SHA256: sum, Match: sum == wantSHA}, nil
}

// Cleanup moves the operation directory holding target (the directory
// itself or a file inside it) to the Trash. It returns ErrBusy, and leaves
// everything in place, while a send still holds a file in it.
func (h *Helper) Cleanup(target string) (*CleanupResult, error) {
	root, err := h.checkRoot()
	if err != nil {
		return nil, err
	}
	opID, err := opIDFor(root, target)
	if err != nil {
		return nil, err
	}
	opDir := filepath.Join(root, opID)
	if err := h.trashOp(opDir); err != nil {
		return nil, err
	}
	return &CleanupResult{OpID: opID, OpDir: opDir, Trashed: true}, nil
}

// Sweep moves operation directories older than MinOrphanAge that no send
// holds to the Trash. Stage runs it before every copy.
func (h *Helper) Sweep() (*SweepResult, error) {
	root, err := h.checkRoot()
	if err != nil {
		return nil, err
	}
	return h.sweep(root), nil
}

func (h *Helper) sweep(root string) *SweepResult {
	res := &SweepResult{}
	entries, err := os.ReadDir(root)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	minAge := h.MinOrphanAge
	if minAge <= 0 {
		minAge = DefaultMinOrphanAge
	}
	now := h.now()
	for _, e := range entries {
		m := opDirPattern.FindStringSubmatch(e.Name())
		if m == nil || !e.IsDir() {
			res.Foreign = append(res.Foreign, e.Name())
			continue
		}
		created, err := time.Parse(opTimeLayout, m[1])
		if err != nil || now.Sub(created) < minAge {
			res.Kept++
			continue
		}
		switch err := h.trashOp(filepath.Join(root, e.Name())); {
		case err == nil:
			res.Recovered = append(res.Recovered, e.Name())
		case errors.Is(err, ErrBusy):
			res.Active = append(res.Active, e.Name())
		default:
			res.Errors = append(res.Errors, err.Error())
		}
	}
	return res
}

func (r *SweepResult) notable() bool {
	return len(r.Recovered) > 0 || len(r.Active) > 0 || len(r.Errors) > 0
}

// trashOp takes an exclusive lock on every regular file in opDir and, if
// none is held by a send, moves the directory to the Trash while the locks
// are still held, so a send cannot start on a file being cleaned up.
func (h *Helper) trashOp(opDir string) error {
	var held []*os.File
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	err := filepath.WalkDir(opDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		held = append(held, f)
		return flock(f, syscall.LOCK_EX)
	})
	if errors.Is(err, ErrBusy) {
		return fmt.Errorf("%s: %w (a send is still in progress; nothing was moved)", opDir, ErrBusy)
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", opDir, err)
	}
	if err := h.trash(opDir); err != nil {
		return fmt.Errorf("move %s to the Trash: %w; the staged copy is still there", opDir, err)
	}
	return nil
}

func (h *Helper) trash(p string) error {
	if h.Trash == nil {
		return errors.New("no Trash command configured")
	}
	return h.Trash(p)
}

func (h *Helper) makeOpDir(r *os.Root) (string, error) {
	for range 8 {
		var b [8]byte
		if _, err := io.ReadFull(h.rand(), b[:]); err != nil {
			return "", fmt.Errorf("generate operation id: %w", err)
		}
		id := h.now().UTC().Format(opTimeLayout) + "-" + hex.EncodeToString(b[:])
		err := r.Mkdir(id, 0o700)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("create operation directory: %w", err)
		}
	}
	return "", errors.New("could not allocate a unique operation directory")
}

// checkRoot resolves the outbound root and refuses one that is missing,
// not a directory, owned by someone else or accessible to group or others.
// Unlike the daemon it never creates the root, so a mistyped path fails.
func (h *Helper) checkRoot() (string, error) {
	if h.Root == "" {
		return "", errors.New("outbound root is not set; pass -root or set WHATSAPP_MCP_OUTBOUND_ROOT")
	}
	if !filepath.IsAbs(h.Root) {
		return "", fmt.Errorf("outbound root %q must be an absolute path", h.Root)
	}
	root, err := filepath.EvalSymlinks(filepath.Clean(h.Root))
	if err != nil {
		return "", fmt.Errorf("outbound root %q: %w (the daemon creates it at startup when WHATSAPP_MCP_OUTBOUND_ROOT is set)", h.Root, err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("outbound root %q: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("outbound root %q is not a directory", root)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return "", fmt.Errorf("outbound root %q is owned by uid %d, not by this user", root, st.Uid)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("outbound root %q has mode %#o; it must be 0700", root, perm)
	}
	return root, nil
}

// opIDFor returns the operation directory name that target belongs to.
func opIDFor(root, target string) (string, error) {
	if target == "" {
		return "", errors.New("cleanup needs the operation directory or the staged file")
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(abs))
	if err != nil {
		return "", fmt.Errorf("%q not accessible: %w", abs, err)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q is not inside the outbound root %q", resolved, root)
	}
	opID := strings.SplitN(rel, string(filepath.Separator), 2)[0]
	if !opDirPattern.MatchString(opID) {
		return "", fmt.Errorf("%q is not in a staging operation directory; cleanup only moves directories created by stage", resolved)
	}
	info, err := os.Lstat(filepath.Join(root, opID))
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%q is not a staging operation directory", filepath.Join(root, opID))
	}
	return opID, nil
}

func checkName(name string) error {
	switch {
	case name == "", name == ".", name == "..", name == string(filepath.Separator):
		return fmt.Errorf("source %q has no usable file name", name)
	case strings.ContainsRune(name, 0):
		return errors.New("source file name contains a NUL byte")
	}
	return nil
}

func normaliseSHA(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("%q is not a SHA-256 hex digest", s)
	}
	return s, nil
}

// digest copies src to dst and returns the SHA-256 and length of the bytes.
func digest(src io.Reader, dst io.Writer) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), src)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func (h *Helper) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Helper) rand() io.Reader {
	if h.Rand != nil {
		return h.Rand
	}
	return rand.Reader
}
