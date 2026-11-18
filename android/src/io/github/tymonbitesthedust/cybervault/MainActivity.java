package io.github.tymonbitesthedust.cybervault;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.util.Base64;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CyberVault for Android.
 *
 * The app itself is the web app in public/, packaged in the APK's assets and served from
 * https://appassets.androidplatform.net (a secure origin, so the browser's crypto and
 * storage work). The Firebase SDK is bundled too, so no code is downloaded at run time.
 * This class adds what a browser tab can't do well on a phone: blocking screenshots,
 * marking copied passwords as sensitive and clearing them, picking or taking photos,
 * saving files, and the back button.
 */
public class MainActivity extends Activity {
    static final String HOST = "appassets.androidplatform.net";
    static final String START_URL = "https://" + HOST + "/index.html";
    static final String FIREBASE_CDN = "https://www.gstatic.com/firebasejs/";
    static final int REQ_PICK = 1;
    static final int REQ_SAVE = 2;

    private WebView web;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Runnable clipboardClear;
    private ValueCallback<Uri[]> fileCallback;
    private Uri pendingCapture;
    private byte[] pendingSave;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        // No screenshots, screen recording or app-switcher previews of the vault.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        cleanCaptures();

        web = new WebView(this);
        web.setBackgroundColor(0xFF050807);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(true);
        s.setSupportMultipleWindows(false);
        s.setMediaPlaybackRequiresUserGesture(true);
        s.setUserAgentString(s.getUserAgentString() + " CyberVaultAndroid/1.0");
        web.addJavascriptInterface(new Bridge(), "CyberVaultAndroid");
        web.setWebViewClient(new Client());
        web.setWebChromeClient(new Chrome());
        setContentView(web);
        web.loadUrl(START_URL);
    }

    // ---------------------------------------------------------------- lifecycle

    @Override
    protected void onPause() {
        js("window.__cvAppState && window.__cvAppState('background')");
        web.onPause();
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        web.onResume();
        js("window.__cvAppState && window.__cvAppState('foreground')");
    }

    @Override
    protected void onDestroy() {
        if (web != null) {
            web.destroy();
            web = null;
        }
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        // Let the app close a panel or go back a screen first.
        web.evaluateJavascript("window.__cvBack ? window.__cvBack() : 'exit'", new ValueCallback<String>() {
            @Override
            public void onReceiveValue(String result) {
                if (result == null || !result.contains("handled")) moveTaskToBack(true);
            }
        });
    }

    private void js(String code) {
        if (web != null) web.evaluateJavascript(code, null);
    }

    private void toast(String text) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show();
    }

    // ---------------------------------------------------------------- serving the app

    private static String mime(String path) {
        String p = path.toLowerCase();
        if (p.endsWith(".html")) return "text/html";
        if (p.endsWith(".js") || p.endsWith(".mjs")) return "text/javascript";
        if (p.endsWith(".css")) return "text/css";
        if (p.endsWith(".svg")) return "image/svg+xml";
        if (p.endsWith(".png")) return "image/png";
        if (p.endsWith(".woff2")) return "font/woff2";
        if (p.endsWith(".json")) return "application/json";
        if (p.endsWith(".webmanifest")) return "application/manifest+json";
        if (p.endsWith(".txt")) return "text/plain";
        return "application/octet-stream";
    }

    private WebResourceResponse asset(String path, boolean cors) {
        if (path.contains("..")) return null;
        try {
            InputStream in = getAssets().open(path);
            Map<String, String> headers = new HashMap<String, String>();
            headers.put("Cache-Control", "no-cache");
            if (cors) headers.put("Access-Control-Allow-Origin", "*");
            String type = mime(path);
            String encoding = type.startsWith("text/") || type.contains("json") || type.contains("svg") ? "utf-8" : null;
            return new WebResourceResponse(type, encoding, 200, "OK", headers, in);
        } catch (IOException e) {
            return null;
        }
    }

    private class Client extends WebViewClient {
        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
            Uri u = request.getUrl();
            if (HOST.equals(u.getHost())) {
                String path = u.getPath();
                if (path == null || path.equals("/") || path.isEmpty()) path = "/index.html";
                WebResourceResponse r = asset("www" + path, false);
                if (r != null) return r;
                return new WebResourceResponse("text/plain", "utf-8", 404, "Not Found", new HashMap<String, String>(), null);
            }
            String url = u.toString();
            if (url.startsWith(FIREBASE_CDN)) {
                // https://www.gstatic.com/firebasejs/<version>/<file>.js → bundled copy, if this version is bundled
                List<String> seg = u.getPathSegments();
                if (seg.size() == 3) {
                    WebResourceResponse r = asset("firebasejs/" + seg.get(1) + "/" + seg.get(2), true);
                    if (r != null) return r;
                }
            }
            return null;
        }

        /** Android 7+: only top-level navigations away from the app open in the browser. */
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            if (!request.isForMainFrame()) return false;
            return leaveApp(request.getUrl());
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            return leaveApp(Uri.parse(url));
        }

        private boolean leaveApp(Uri u) {
            if (HOST.equals(u.getHost())) return false;
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, u));
            } catch (ActivityNotFoundException e) {
                toast("No app can open that link.");
            }
            return true;
        }
    }

    // ---------------------------------------------------------------- picking and taking photos

    private void cleanCaptures() {
        File[] old = CaptureProvider.dir(this).listFiles();
        if (old != null) for (File f : old) f.delete();
    }

    private Intent captureIntent() {
        Intent cam = new Intent("android.media.action.IMAGE_CAPTURE");
        if (cam.resolveActivity(getPackageManager()) == null) return null;
        File dir = CaptureProvider.dir(this);
        dir.mkdirs();
        File f = new File(dir, "photo-" + System.currentTimeMillis() + ".jpg");
        pendingCapture = CaptureProvider.uriFor(f);
        cam.putExtra("output", pendingCapture); // MediaStore.EXTRA_OUTPUT
        cam.setClipData(ClipData.newRawUri("", pendingCapture));
        cam.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        return cam;
    }

    private class Chrome extends WebChromeClient {
        @Override
        public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
            if (fileCallback != null) fileCallback.onReceiveValue(null);
            fileCallback = callback;
            pendingCapture = null;

            boolean images = false;
            String[] types = params.getAcceptTypes();
            if (types != null) for (String t : types) if (t != null && t.startsWith("image/")) images = true;

            Intent pick = new Intent(Intent.ACTION_GET_CONTENT);
            pick.addCategory(Intent.CATEGORY_OPENABLE);
            pick.setType(images ? "image/*" : "*/*");
            if (params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE) pick.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);

            Intent chooser = Intent.createChooser(pick, images ? "Add a photo" : "Choose a file");
            if (images) {
                Intent cam = captureIntent();
                if (cam != null) chooser.putExtra(Intent.EXTRA_INITIAL_INTENTS, new Intent[] {cam});
            }
            try {
                startActivityForResult(chooser, REQ_PICK);
            } catch (ActivityNotFoundException e) {
                fileCallback = null;
                callback.onReceiveValue(null);
                toast("No app can pick files.");
            }
            return true;
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (request == REQ_PICK) {
            ValueCallback<Uri[]> cb = fileCallback;
            fileCallback = null;
            if (cb == null) return;
            Uri[] picked = null;
            if (result == RESULT_OK) {
                if (data != null && data.getClipData() != null && data.getClipData().getItemCount() > 0
                        && data.getData() == null) {
                    List<Uri> list = new ArrayList<Uri>();
                    ClipData clip = data.getClipData();
                    for (int i = 0; i < clip.getItemCount(); i++) {
                        Uri u = clip.getItemAt(i).getUri();
                        if (u != null && !u.equals(pendingCapture)) list.add(u);
                    }
                    if (!list.isEmpty()) picked = list.toArray(new Uri[0]);
                } else if (data != null && data.getData() != null) {
                    picked = new Uri[] {data.getData()};
                }
                if (picked == null && pendingCapture != null) {
                    // The camera returns no data; the photo is in our temporary file.
                    File f = new File(CaptureProvider.dir(this), pendingCapture.getLastPathSegment());
                    if (f.length() > 0) picked = new Uri[] {pendingCapture};
                }
            }
            cb.onReceiveValue(picked);
            return;
        }
        if (request == REQ_SAVE) {
            byte[] bytes = pendingSave;
            pendingSave = null;
            if (result != RESULT_OK || data == null || data.getData() == null || bytes == null) return;
            try {
                OutputStream out = getContentResolver().openOutputStream(data.getData());
                out.write(bytes);
                out.close();
                toast("Saved");
            } catch (Exception e) {
                toast("Couldn't save the file.");
            }
            return;
        }
        super.onActivityResult(request, result, data);
    }

    // ---------------------------------------------------------------- clipboard

    private void setClipboard(String text, boolean sensitive, int clearSeconds) {
        final ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(sensitive ? "CyberVault (hidden)" : "CyberVault", text);
        if (sensitive && Build.VERSION.SDK_INT >= 24) {
            // Android 13+ hides "sensitive" clips in the copy preview and keyboard suggestions.
            try {
                PersistableBundle extras = new PersistableBundle();
                extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
                ClipDescription.class.getMethod("setExtras", PersistableBundle.class).invoke(clip.getDescription(), extras);
            } catch (Exception ignored) {
                // older Android: nothing to do
            }
        }
        cm.setPrimaryClip(clip);
        if (clipboardClear != null) handler.removeCallbacks(clipboardClear);
        clipboardClear = null;
        if (clearSeconds > 0) {
            final String copied = text;
            clipboardClear = new Runnable() {
                @Override
                public void run() {
                    clearClipboard(cm, copied);
                }
            };
            handler.postDelayed(clipboardClear, clearSeconds * 1000L);
        }
    }

    private void clearClipboard(ClipboardManager cm, String copied) {
        try {
            ClipData current = cm.getPrimaryClip();
            if (current != null && current.getItemCount() > 0) {
                CharSequence now = current.getItemAt(0).getText();
                if (now != null && !now.toString().equals(copied)) return; // something else was copied since
            }
            if (Build.VERSION.SDK_INT >= 28) {
                ClipboardManager.class.getMethod("clearPrimaryClip").invoke(cm);
            } else {
                cm.setPrimaryClip(ClipData.newPlainText("", ""));
            }
        } catch (Exception ignored) {
            // best effort
        }
    }

    // ---------------------------------------------------------------- bridge for app.js

    /** Exposed to the page as window.CyberVaultAndroid. Only our own bundled page is ever loaded. */
    private class Bridge {
        @JavascriptInterface
        public boolean copyText(final String text, final boolean sensitive, final int clearSeconds) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    setClipboard(text, sensitive, clearSeconds);
                }
            });
            return true;
        }

        @JavascriptInterface
        public void saveFile(final String name, final String mime, String base64) {
            final byte[] bytes = Base64.decode(base64, Base64.DEFAULT);
            handler.post(new Runnable() {
                @Override
                public void run() {
                    pendingSave = bytes;
                    Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    save.addCategory(Intent.CATEGORY_OPENABLE);
                    save.setType(mime == null || mime.isEmpty() ? "application/octet-stream" : mime);
                    save.putExtra(Intent.EXTRA_TITLE, name);
                    try {
                        startActivityForResult(save, REQ_SAVE);
                    } catch (ActivityNotFoundException e) {
                        pendingSave = null;
                        toast("No app can save files.");
                    }
                }
            });
        }

        @JavascriptInterface
        public String version() {
            return "1.0";
        }
    }
}
