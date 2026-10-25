// Package security holds policy-layer helpers used across the MCP bridge:
// path allowlisting for outbound media, filename sanitisation for inbound
// documents, and a log redactor for JIDs and message bodies.
package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ErrOutsideRoot is wrapped by every error that rejects a path because it
// resolves outside its allowed root.
var ErrOutsideRoot = errors.New("outside allowed root")

// MediaRootHint is the remedy appended to out-of-root errors for the legacy
// single media root.
const MediaRootHint = "set WHATSAPP_MCP_MEDIA_ROOT or place the file under that root"

// OpenOptions tunes OpenRegular for the root it guards.
type OpenOptions struct {
	Field      string // argument name used in errors, e.g. "media_path"
	Hint       string // remedy appended to out-of-root errors
	RequireAbs bool   // refuse relative paths instead of resolving them against the cwd
	SingleLink bool   // refuse files with more than one hard link
}

// testHookBeforeOpen runs between path resolution and the confined open so
// tests can swap path components in that window.
var testHookBeforeOpen func()

// OpenRegular opens the existing regular file at userPath for reading,
// confined to root, and returns it with its symlink-resolved path.
//
// Resolution only decides which name inside root is meant. The open itself
// goes through os.Root, which walks every component with O_NOFOLLOW and
// refuses symlinks that leave the root, so swapping a file or a parent
// directory after resolution can at worst open another file inside root.
// The type checks run on the opened descriptor: FIFOs are opened
// non-blocking and rejected like directories and devices.
func OpenRegular(userPath, root string, opts OpenOptions) (*os.File, string, error) {
	field := opts.Field
	if field == "" {
		field = "path"
	}
	if userPath == "" {
		return nil, "", fmt.Errorf("%s is required", field)
	}
	if opts.RequireAbs && !filepath.IsAbs(userPath) {
		return nil, "", fmt.Errorf("%s %q must be an absolute path", field, userPath)
	}
	abs, err := filepath.Abs(userPath)
	if err != nil {
		return nil, "", fmt.Errorf("invalid %s %q: %w", field, userPath, err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(abs))
	if err != nil {
		return nil, "", fmt.Errorf("%s %q not accessible: %w", field, abs, err)
	}
	rootResolved, err := resolveRoot(root)
	if err != nil {
		return nil, "", err
	}
	if err := confine(field, resolved, rootResolved, opts.Hint); err != nil {
		return nil, resolved, err
	}
	rel, err := filepath.Rel(rootResolved, resolved)
	if err != nil {
		return nil, resolved, fmt.Errorf("%s %q: %w", field, resolved, err)
	}
	if testHookBeforeOpen != nil {
		testHookBeforeOpen()
	}
	r, err := os.OpenRoot(rootResolved)
	if err != nil {
		return nil, resolved, fmt.Errorf("open allowed root %q: %w", rootResolved, err)
	}
	defer r.Close()
	f, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, resolved, fmt.Errorf("%s %q could not be opened inside %q: %w", field, resolved, rootResolved, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, resolved, fmt.Errorf("stat %s %q: %w", field, resolved, err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, resolved, fmt.Errorf("%s %q is not a regular file (%s)", field, resolved, describeType(info.Mode()))
	}
	if opts.SingleLink {
		if n := LinkCount(info); n != 1 {
			f.Close()
			return nil, resolved, fmt.Errorf("%s %q has %d hard links; stage an independent copy instead of a link", field, resolved, n)
		}
	}
	return f, resolved, nil
}

// describeType names the non-regular file kinds OpenRegular refuses.
func describeType(m os.FileMode) string {
	switch {
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "directory"
	case m&os.ModeNamedPipe != 0:
		return "named pipe"
	case m&os.ModeDevice != 0:
		return "device"
	case m&os.ModeSocket != 0:
		return "socket"
	default:
		return "irregular file"
	}
}

// LinkCount returns the hard-link count of a file, or 0 when the platform
// does not report it.
func LinkCount(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

// resolveRoot returns allowedRoot absolute, cleaned, and symlink-resolved.
// A root that does not exist yet falls back to its cleaned absolute form.
func resolveRoot(allowedRoot string) (string, error) {
	rootAbs, err := filepath.Abs(allowedRoot)
	if err != nil {
		return "", fmt.Errorf("invalid allowed root %q: %w", allowedRoot, err)
	}
	rootAbs = filepath.Clean(rootAbs)
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return rootAbs, nil
	}
	return rootResolved, nil
}

// within reports whether p is root itself or lies under it. Both paths
// must already be clean and absolute.
func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// Within reports whether path resolves to root or below it, resolving
// symlinks on both sides where they exist.
func Within(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	p, err := canonicalPath(path)
	if err != nil {
		return false
	}
	r, err := canonicalPath(root)
	if err != nil {
		return false
	}
	return within(p, r)
}

// confine rejects resolved paths that are neither root itself nor under it;
// field names the offending parameter in the error and hint the remedy.
func confine(field, resolved, root, hint string) error {
	if within(resolved, root) {
		return nil
	}
	if hint == "" {
		hint = MediaRootHint
	}
	return fmt.Errorf("%s %q is %w %q; %s", field, resolved, ErrOutsideRoot, root, hint)
}

// Target is a path inside a root resolved up to its parent directory:
// Root is the symlink-resolved allowed root and Rel the path relative to it.
// The final component is deliberately left unresolved, and every access
// goes through os.Root, so neither a symlink at the final component nor a
// parent directory swapped after validation can reach outside Root.
type Target struct {
	Root string
	Rel  string
	Path string // Root joined with Rel, as reported to callers
}

// ResolveTarget resolves userPath's parent directory through symlinks,
// re-anchors the basename and confines the result inside allowedRoot;
// field names the argument in errors. Only the parent has to exist.
func ResolveTarget(field, userPath, allowedRoot string) (*Target, error) {
	if userPath == "" {
		return nil, fmt.Errorf("%s is required when provided", field)
	}
	abs, err := filepath.Abs(userPath)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: %w", field, userPath, err)
	}
	abs = filepath.Clean(abs)
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("%s parent directory %q not accessible: %w", field, parent, err)
	}
	resolved := filepath.Join(resolvedParent, filepath.Base(abs))

	rootResolved, err := resolveRoot(allowedRoot)
	if err != nil {
		return nil, err
	}
	if err := confine(field, resolved, rootResolved, MediaRootHint); err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(rootResolved, resolved)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", field, resolved, err)
	}
	return &Target{Root: rootResolved, Rel: rel, Path: resolved}, nil
}

// ResolveOutputPath validates download_media's output_path: a file the
// daemon is about to create under allowedRoot.
func ResolveOutputPath(userPath, allowedRoot string) (*Target, error) {
	return ResolveTarget("output_path", userPath, allowedRoot)
}

func (t *Target) inRoot(fn func(r *os.Root) error) error {
	r, err := os.OpenRoot(t.Root)
	if err != nil {
		return err
	}
	defer r.Close()
	return fn(r)
}

// Lstat describes the target without following a symlink at its final
// component.
func (t *Target) Lstat() (info os.FileInfo, err error) {
	err = t.inRoot(func(r *os.Root) error {
		info, err = r.Lstat(t.Rel)
		return err
	})
	return info, err
}

// CreateExclusive creates the target with mode 0600. It fails with
// fs.ErrExist when anything, including a dangling symlink, already sits there.
func (t *Target) CreateExclusive() (f *os.File, err error) {
	err = t.inRoot(func(r *os.Root) error {
		f, err = r.OpenFile(t.Rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		return err
	})
	return f, err
}

// Remove deletes the target (used to drop a partial write).
func (t *Target) Remove() error {
	return t.inRoot(func(r *os.Root) error { return r.Remove(t.Rel) })
}

// OpenRegular opens the target for reading only if it is a regular file
// and not a symlink. The descriptor is compared with the Lstat taken just
// before, so a symlink swapped in between is refused instead of followed.
func (t *Target) OpenRegular() (f *os.File, err error) {
	err = t.inRoot(func(r *os.Root) error {
		before, err := r.Lstat(t.Rel)
		if err != nil {
			return err
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("%q is not a regular file (%s)", t.Path, describeType(before.Mode()))
		}
		opened, err := r.OpenFile(t.Rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		info, err := opened.Stat()
		if err != nil || !os.SameFile(before, info) {
			opened.Close()
			return fmt.Errorf("%q changed while it was being opened", t.Path)
		}
		f = opened
		return nil
	})
	return f, err
}

// DedicatedRootPolicy lists the paths a dedicated root must stay clear of.
type DedicatedRootPolicy struct {
	// Protected paths may not be the root or lie under it (home, the daemon
	// store, the system temp directories). A root below them is fine.
	Protected []string
	// Disjoint paths may not overlap the root in either direction (the
	// inbound media root).
	Disjoint []string
}

// PrepareDedicatedRoot validates a root that must hold nothing but the
// files staged for it, creates it with mode 0700 when missing and returns
// its symlink-resolved path. It fails closed: a relative path, a root that
// contains a protected path or overlaps a disjoint one, a non-directory, a
// directory owned by another user or one that group or others can access
// are all refused with an error naming the remedy.
func PrepareDedicatedRoot(name, root string, p DedicatedRootPolicy) (string, error) {
	if root == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("%s %q must be an absolute path", name, root)
	}
	clean := filepath.Clean(root)
	canon, err := canonicalPath(clean)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", name, clean, err)
	}
	if err := checkDedicated(name, canon, p); err != nil {
		return "", err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return "", fmt.Errorf("create %s %q: %w", name, clean, err)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", name, clean, err)
	}
	if err := checkDedicated(name, resolved, p); err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", name, resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s %q is not a directory", name, resolved)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return "", fmt.Errorf("%s %q is owned by uid %d, not by this user", name, resolved, st.Uid)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s %q has mode %#o; group and others must have no access (chmod 700 %s)", name, resolved, perm, resolved)
	}
	return resolved, nil
}

func checkDedicated(name, canon string, p DedicatedRootPolicy) error {
	if canon == string(filepath.Separator) {
		return fmt.Errorf("%s %q is the filesystem root", name, canon)
	}
	for _, prot := range p.Protected {
		if prot == "" {
			continue
		}
		cp, err := canonicalPath(prot)
		if err != nil {
			return fmt.Errorf("%s: resolve %q: %w", name, prot, err)
		}
		if within(cp, canon) {
			return fmt.Errorf("%s %q contains %q; point it at a dedicated directory below it", name, canon, cp)
		}
	}
	for _, d := range p.Disjoint {
		if d == "" {
			continue
		}
		cd, err := canonicalPath(d)
		if err != nil {
			return fmt.Errorf("%s: resolve %q: %w", name, d, err)
		}
		if within(cd, canon) || within(canon, cd) {
			return fmt.Errorf("%s %q overlaps %q; the two roots must be separate directories", name, canon, cd)
		}
	}
	return nil
}

// canonicalPath returns p absolute and clean with symlinks resolved in the
// longest prefix that exists; the missing remainder is appended unchanged.
func canonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	var rest []string
	cur := abs
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for i := len(rest) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, rest[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = append(rest, filepath.Base(cur))
		cur = parent
	}
}

// SafeFilename returns filepath.Base(raw) unless the base is one of the
// degenerate values that could escape a join or hit special-case behaviour
// ("", ".", "..", "/", or contains a null byte), in which case it returns
// a timestamped fallback of the form "document_YYYYMMDD_HHMMSS". Matches
// the old whatsapp-bridge behaviour.
func SafeFilename(raw string) string {
	if strings.ContainsRune(raw, '\x00') {
		return fallbackFilename()
	}
	base := filepath.Base(raw)
	switch base {
	case "", ".", "..", "/":
		return fallbackFilename()
	}
	return base
}

func fallbackFilename() string {
	return "document_" + time.Now().UTC().Format("20060102_150405")
}
