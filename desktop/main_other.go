//go:build !windows

// For development on Linux or macOS: serves exactly what the Windows app shows, so it can be
// tried in a browser. Build the real app with tools/build-exe.sh.
package main

import "fmt"

func main() {
	base := startServer()
	fmt.Printf("CyberVault (Windows app page) at %s/\nPress Ctrl+C to stop.\n", base)
	select {}
}
