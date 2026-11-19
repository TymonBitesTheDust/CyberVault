package main

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
)

// The app's files: the web app from public/ (assets/www) and the Firebase SDK
// (assets/firebasejs), copied here by tools/build-exe.sh before building.
//
//go:embed all:assets
var assets embed.FS

const marker = "cybervault-desktop"

// Fixed ports keep the page's address the same between runs, and with it everything the page
// keeps on this PC: the Firebase connection, settings and the encrypted offline copy.
var ports = []int{47861, 47862, 47863, 47864, 47865}

// Explicit types: on Windows, Go's lookup reads the registry, where .js is sometimes
// "text/plain", which browsers refuse for modules.
var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".woff2":       "font/woff2",
	".json":        "application/json",
	".webmanifest": "application/manifest+json",
	".txt":         "text/plain; charset=utf-8",
}

// startServer serves the bundled app on 127.0.0.1 and returns its base URL.
func startServer() string {
	ln, port := listen()
	if ln != nil {
		go func() { _ = http.Serve(ln, handler(port)) }()
	}
	return fmt.Sprintf("http://localhost:%d", port)
}

func listen() (net.Listener, int) {
	for _, p := range ports {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, p
		}
		// Port taken: if it's CyberVault already running, use that.
		if isOurs(addr) {
			return nil, p
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func isOurs(addr string) bool {
	c := http.Client{Timeout: 800 * time.Millisecond}
	r, err := c.Get("http://" + addr + "/__id")
	if err != nil {
		return false
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 64))
	return strings.TrimSpace(string(b)) == marker
}

func handler(port int) http.Handler {
	www, _ := fs.Sub(assets, "assets/www")
	sdk, _ := fs.Sub(assets, "assets/firebasejs")
	allowed := map[string]bool{
		fmt.Sprintf("localhost:%d", port): true,
		fmt.Sprintf("127.0.0.1:%d", port): true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/__id", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(marker))
	})
	mux.Handle("/firebasejs/", http.StripPrefix("/firebasejs", files(sdk)))
	mux.Handle("/", files(www))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only answer requests addressed to this PC (blocks DNS-rebinding tricks).
		if !allowed[r.Host] {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// files serves read-only files from root, with no directory listings.
func files(root fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		b, err := fs.ReadFile(root, p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		ct, ok := contentTypes[path.Ext(p)]
		if !ok {
			ct = "application/octet-stream"
		}
		h.Set("Content-Type", ct)
		h.Set("Cache-Control", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(b)
	})
}
