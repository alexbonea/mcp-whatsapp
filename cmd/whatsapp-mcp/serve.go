package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/daemon"
	mcpsrv "github.com/sealjay/mcp-whatsapp/internal/mcp"
	"github.com/sealjay/mcp-whatsapp/internal/security"
	"github.com/sealjay/mcp-whatsapp/internal/store"
)

func runServe(storeDir string, redactor *security.Redactor, args []string) int {
	var (
		addr        string
		allowRemote bool
	)
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&addr, "addr", "", "HTTP bind address (default: 127.0.0.1:8765, env WHATSAPP_MCP_ADDR)")
	fs.BoolVar(&allowRemote, "allow-remote", false, "allow binding to a non-loopback address")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	addr = resolveAddr(addr)
	if !allowRemote && !isLoopbackAddr(addr) {
		fmt.Fprintf(os.Stderr, "refusing to bind to non-loopback address %q; pass -allow-remote if you mean it\n", addr)
		return 2
	}

	// When binding to a non-loopback address we require a shared bearer
	// token. Loopback-only operation intentionally keeps no token so local
	// editors and curl can hit the daemon without extra setup.
	var authToken string
	if allowRemote {
		authToken = os.Getenv("WHATSAPP_MCP_TOKEN")
		if authToken == "" {
			fmt.Fprintln(os.Stderr, "-allow-remote requires WHATSAPP_MCP_TOKEN to be set in the environment")
			return 2
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	lock, err := store.TryLock(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	defer lock.Release()

	absStore, err := filepath.Abs(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve store dir: %v\n", err)
		return 1
	}
	roots, err := resolveMediaRoots(absStore, os.Getenv("WHATSAPP_MCP_MEDIA_ROOT"), os.Getenv("WHATSAPP_MCP_OUTBOUND_ROOT"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "refusing to start: %v\n", err)
		return 2
	}
	// Operator UX: make the roots obvious on boot so users know where
	// received media lands and where outbound attachments must sit.
	if roots.outbound == "" {
		fmt.Fprintf(os.Stderr, "media root: %s (download_media output_path and outbound media_path; set WHATSAPP_MCP_OUTBOUND_ROOT to give sends their own root)\n", roots.inbound)
	} else {
		fmt.Fprintf(os.Stderr, "media root: %s (download_media output_path only)\n", roots.inbound)
		fmt.Fprintf(os.Stderr, "outbound root: %s (send_file and send_audio_message media_path; stage copies with `whatsapp-mcp outbound stage`)\n", roots.outbound)
	}

	st, err := store.Open(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		return 1
	}
	defer st.Close()

	c, err := client.New(ctx, client.Config{
		StoreDir:         storeDir,
		Store:            st,
		Logger:           client.NewStderrLogger("Client", "INFO", false),
		AllowedMediaRoot: roots.inbound,
		OutboundRoot:     roots.outbound,
		Redactor:         redactor,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client: %v\n", err)
		return 1
	}

	drv := newProductionDriver(c)

	// The daemon owns the pair cache, so build it first, then hand the cache
	// to the MCP server (so pairing_status can surface the live QR), then
	// mount the MCP HTTP handler back onto the daemon.
	d, err := daemon.New(daemon.Config{
		Addr:      addr,
		Driver:    drv,
		AuthToken: authToken,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon.New: %v\n", err)
		return 1
	}

	mcpServer := mcpsrv.NewServer(c, d.Cache())
	d.SetMCPMount(mcpServer.AttachHTTP)

	fmt.Fprintf(os.Stderr, "whatsapp-mcp listening on http://%s (MCP at /mcp, pairing at /pair)\n", addr)
	if !c.IsLoggedIn() {
		fmt.Fprintf(os.Stderr, "unpaired: open http://%s/pair to scan QR\n", addr)
	}
	if err := d.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "daemon: %v\n", err)
		return 1
	}
	return 0
}

// mediaRoots holds the inbound media root and the optional dedicated
// outbound root.
type mediaRoots struct {
	inbound  string // download_media output_path; also send media_path when outbound is empty
	outbound string // symlink-resolved WHATSAPP_MCP_OUTBOUND_ROOT, or empty for the legacy single root
}

// resolveMediaRoots applies the root configuration. WHATSAPP_MCP_MEDIA_ROOT
// keeps its legacy meaning and defaults; a missing directory is created
// best-effort. WHATSAPP_MCP_OUTBOUND_ROOT, when set, becomes the only root
// sends read from and must be a dedicated private directory: it may not
// contain home, the store or a system temp directory, may not overlap the
// media root, and must be (or is created as) a 0700 directory of this user.
func resolveMediaRoots(absStore, mediaEnv, outboundEnv string) (mediaRoots, error) {
	inbound := mediaEnv
	if inbound == "" {
		inbound = filepath.Join(absStore, "uploads")
	}
	inbound = filepath.Clean(inbound)
	if mkErr := os.MkdirAll(inbound, 0o755); mkErr != nil {
		fmt.Fprintf(os.Stderr, "warn: could not create media root %q: %v\n", inbound, mkErr)
	}
	if outboundEnv == "" {
		return mediaRoots{inbound: inbound}, nil
	}
	var protected []string
	if home, err := os.UserHomeDir(); err == nil {
		protected = append(protected, home)
	}
	protected = append(protected, absStore, os.TempDir(), "/tmp", "/var/tmp")
	outbound, err := security.PrepareDedicatedRoot("WHATSAPP_MCP_OUTBOUND_ROOT", outboundEnv, security.DedicatedRootPolicy{
		Protected: protected,
		Disjoint:  []string{inbound},
	})
	if err != nil {
		return mediaRoots{}, err
	}
	return mediaRoots{inbound: inbound, outbound: outbound}, nil
}

// resolveAddr applies the -addr / WHATSAPP_MCP_ADDR / default precedence.
func resolveAddr(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("WHATSAPP_MCP_ADDR"); env != "" {
		return env
	}
	return "127.0.0.1:8765"
}

// isLoopbackAddr reports whether addr's host resolves to a loopback IP.
// Hostnames (including "localhost") are resolved via DNS; all returned
// addresses must be loopback for the check to pass. Non-loopback binds
// require -allow-remote.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	// If it parses directly as an IP, check without DNS.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// Resolve hostname and require every address to be loopback.
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}
