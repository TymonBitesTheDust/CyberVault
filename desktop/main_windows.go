//go:build windows

// CyberVault for Windows: a native window (Microsoft Edge WebView2, built into Windows 10
// and 11) showing the bundled web app. The app is served from a fixed address on this PC
// only, so the data it keeps here (Firebase connection, settings, encrypted offline copy)
// stays between runs, in %LOCALAPPDATA%\CyberVault.
package main

import (
	"net/url"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const (
	appName   = "CyberVault"
	iconResID = 1
)

var (
	user32         = windows.NewLazySystemDLL("user32.dll")
	dwmapi         = windows.NewLazySystemDLL("dwmapi.dll")
	procFindWindow = user32.NewProc("FindWindowW")
	procShowWindow = user32.NewProc("ShowWindow")
	procSetFg      = user32.NewProc("SetForegroundWindow")
	procIsIconic   = user32.NewProc("IsIconic")
	procMessageBox = user32.NewProc("MessageBoxW")
	procGetDpi     = user32.NewProc("GetDpiForSystem")
	procSysMetrics = user32.NewProc("GetSystemMetrics")
	procDwmSetAttr = dwmapi.NewProc("DwmSetWindowAttribute")
)

func main() {
	// One window at a time: opening it again brings the first one forward.
	name, _ := windows.UTF16PtrFromString("Local\\CyberVaultDesktopSingleInstance")
	mutex, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		focusExisting()
		return
	}
	defer windows.CloseHandle(mutex)

	base := startServer()

	dataDir := filepath.Join(os.Getenv("LOCALAPPDATA"), appName)
	_ = os.MkdirAll(dataDir, 0o700)

	width, height := windowSize()
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     os.Getenv("CYBERVAULT_DEBUG") == "1",
		AutoFocus: true,
		DataPath:  dataDir,
		WindowOptions: webview2.WindowOptions{
			Title:  appName,
			Width:  width,
			Height: height,
			IconId: iconResID,
			Center: true,
		},
	})
	if w == nil {
		fallback(base)
		return
	}
	defer w.Destroy()

	hwnd := uintptr(w.Window())
	darkTitleBar(hwnd)
	w.SetSize(int(scale(380)), int(scale(560)), webview2.HintMin)

	// Websites (links in items, About, the Firebase console…) open in the PC's own browser.
	_ = w.Bind("cvOpenExternal", func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "mailto") {
			return
		}
		openURL(u.String())
	})

	w.Navigate(base + "/")
	w.Run()
}

// ---------------------------------------------------------------- window helpers

func dpi() uintptr {
	if procGetDpi.Find() == nil {
		if d, _, _ := procGetDpi.Call(); d > 0 {
			return d
		}
	}
	return 96
}

func scale(v uint) uint { return uint(uintptr(v) * dpi() / 96) }

// A tall, phone-like window, which suits the app's layout, kept inside the screen.
func windowSize() (uint, uint) {
	w, h := scale(560), scale(900)
	sw, _, _ := procSysMetrics.Call(0) // SM_CXSCREEN
	sh, _, _ := procSysMetrics.Call(1) // SM_CYSCREEN
	if sw > 0 && uint(sw)*9/10 < w {
		w = uint(sw) * 9 / 10
	}
	if sh > 0 && uint(sh)*85/100 < h {
		h = uint(sh) * 85 / 100
	}
	return w, h
}

// A dark title bar to match the app (Windows 10 20H1 and newer; ignored elsewhere).
func darkTitleBar(hwnd uintptr) {
	if procDwmSetAttr.Find() != nil {
		return
	}
	on := int32(1)
	procDwmSetAttr.Call(hwnd, 20, uintptr(unsafe.Pointer(&on)), unsafe.Sizeof(on)) // DWMWA_USE_IMMERSIVE_DARK_MODE
}

func focusExisting() {
	class, _ := windows.UTF16PtrFromString("webview")
	title, _ := windows.UTF16PtrFromString(appName)
	hwnd, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return
	}
	if iconic, _, _ := procIsIconic.Call(hwnd); iconic != 0 {
		procShowWindow.Call(hwnd, 9) // SW_RESTORE
	}
	procSetFg.Call(hwnd)
}

func openURL(u string) {
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(u)
	_ = windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

func messageBox(text, caption string, flags uintptr) uintptr {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(caption)
	r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
	return r
}

// No WebView2 runtime (rare: it comes with Windows 11 and up-to-date Windows 10). Offer the
// download, or use CyberVault in the browser for now.
func fallback(base string) {
	const yes = 6
	r := messageBox("CyberVault needs the Microsoft Edge WebView2 Runtime, which is missing on this PC.\n\n"+
		"Choose Yes to download it from Microsoft (free, about 2 minutes), then open CyberVault again.\n"+
		"Choose No to use CyberVault in your web browser for now. Keep this message open while you use it.",
		appName, 0x00000004|0x00000030) // MB_YESNO | MB_ICONWARNING
	if r == yes {
		openURL("https://go.microsoft.com/fwlink/p/?LinkId=2124703")
		return
	}
	openURL(base + "/")
	messageBox("CyberVault is running in your browser. Close this message to quit.", appName, 0x00000040)
}
