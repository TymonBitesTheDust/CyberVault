package main

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testPort = 47861

func get(t *testing.T, h http.Handler, method, host, target string) *http.Response {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func needAssets(t *testing.T) {
	t.Helper()
	if _, err := fs.Stat(assets, "assets/www/index.html"); err != nil {
		t.Skip("run tools/build-exe.sh first, so desktop/assets has the app")
	}
}

func TestServesTheApp(t *testing.T) {
	needAssets(t)
	h := handler(testPort)
	res := get(t, h, "GET", "localhost:47861", "/")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(body), `<meta name="cybervault-shell" content="windows">`) {
		t.Fatalf("index: %d, marked as Windows app: %v", res.StatusCode, strings.Contains(string(body), "cybervault-shell"))
	}
	if got := res.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("index type %q", got)
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

func TestScriptsAreJavaScriptAndUseBundledFirebase(t *testing.T) {
	needAssets(t)
	h := handler(testPort)
	for _, p := range []string{"/app.js", "/vault-crypto.js", "/qr.js", "/firebasejs/13.3.0/firebase-firestore.js"} {
		res := get(t, h, "GET", "127.0.0.1:47861", p)
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
		if got := res.Header.Get("Content-Type"); got != "text/javascript; charset=utf-8" {
			t.Errorf("%s type %q", p, got)
		}
		if strings.Contains(string(body), "https://www.gstatic.com/firebasejs/") {
			t.Errorf("%s still loads Firebase from the internet", p)
		}
	}
}

func TestNoServiceWorkerOrStrayFiles(t *testing.T) {
	needAssets(t)
	h := handler(testPort)
	for _, p := range []string{"/sw.js", "/manifest.webmanifest", "/nope.js"} {
		if res := get(t, h, "GET", "localhost:47861", p); res.StatusCode != 404 {
			t.Errorf("%s: want 404, got %d", p, res.StatusCode)
		}
	}
	// Paths that try to climb out are redirected to their cleaned form, which doesn't exist.
	for _, p := range []string{"/../desktop/server.go", "/firebasejs/../www/app.js", "/%2e%2e/go.mod"} {
		res := get(t, h, "GET", "localhost:47861", p)
		if res.StatusCode == 200 {
			t.Errorf("%s: served a file", p)
			continue
		}
		if loc := res.Header.Get("Location"); loc != "" {
			if res2 := get(t, h, "GET", "localhost:47861", loc); res2.StatusCode != 404 {
				t.Errorf("%s → %s: want 404, got %d", p, loc, res2.StatusCode)
			}
		}
	}
}

func TestOnlyThisPCAndOnlyReads(t *testing.T) {
	needAssets(t)
	h := handler(testPort)
	if res := get(t, h, "GET", "evil.example:47861", "/"); res.StatusCode != 403 {
		t.Errorf("other host: want 403, got %d", res.StatusCode)
	}
	if res := get(t, h, "POST", "localhost:47861", "/"); res.StatusCode != 405 {
		t.Errorf("POST: want 405, got %d", res.StatusCode)
	}
	if res := get(t, h, "GET", "localhost:47861", "/__id"); res.StatusCode != 200 {
		t.Errorf("/__id: %d", res.StatusCode)
	}
}

func TestSecondCopyReusesTheFirst(t *testing.T) {
	needAssets(t)
	ln, port := listen()
	if ln == nil {
		t.Skip("a CyberVault is already running here")
	}
	defer ln.Close()
	go func() { _ = http.Serve(ln, handler(port)) }()
	ln2, port2 := listen()
	if ln2 != nil {
		ln2.Close()
	}
	if ln2 != nil || port2 != port {
		t.Fatalf("second start: listener=%v port=%d, want reuse of %d", ln2 != nil, port2, port)
	}
}
