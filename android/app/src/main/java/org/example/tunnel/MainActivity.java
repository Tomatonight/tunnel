package org.example.tunnel;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.JavascriptInterface;
import android.webkit.JsResult;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import org.json.JSONObject;
import org.json.JSONException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;
import java.security.MessageDigest;

public final class MainActivity extends Activity {
    private static final String ORIGIN = "https://tunnel.local";
    private static final int VPN_PERMISSION = 1, PICK_CONFIG = 2;
    private static final Object configurationGate = new Object();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private WebView web;
    private ValueCallback<Uri[]> fileSelection;
    private AlertDialog confirmation;
    private JsResult confirmationResult;
    private volatile boolean trustedPage, destroyed;
    private volatile long pendingStart;
    private boolean consentRequested;
    private File configFile() { return new File(getFilesDir(), "configure.json"); }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if (state != null) { pendingStart = state.getLong("pendingStart", 0); consentRequested = state.getBoolean("consentRequested", false); }
        web = new WebView(this);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(false);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setBlockNetworkLoads(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSupportMultipleWindows(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        web.addJavascriptInterface(new Host(), "TunnelHost");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return !isIndex(request.getUrl());
            }
            @Override public void onPageStarted(WebView view, String url, android.graphics.Bitmap icon) {
                trustedPage = isIndex(Uri.parse(url));
            }
            @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                String path = url.getPath();
                boolean local = "https".equals(url.getScheme()) && "tunnel.local".equals(url.getHost())
                    && url.getPort() == -1 && url.getUserInfo() == null && "GET".equals(request.getMethod());
                String asset = "/".equals(path) ? "index.html"
                    : path == null || path.isEmpty() || !path.startsWith("/") ? "" : path.substring(1);
                if (!local || !(asset.equals("index.html") || asset.equals("app.js") || asset.equals("app.css")))
                    return blocked();
                try {
                    String mime = asset.endsWith(".js") ? "text/javascript" : asset.endsWith(".css") ? "text/css" : "text/html";
                    Map<String, String> headers = new HashMap<>();
                    headers.put("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'");
                    headers.put("X-Content-Type-Options", "nosniff");
                    headers.put("Cache-Control", "no-store");
                    return new WebResourceResponse(mime, "UTF-8", 200, "OK", headers, getAssets().open(asset));
                } catch (Exception error) { return blocked(); }
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onJsConfirm(WebView view, String url, String message, JsResult result) {
                if (!trustedPage || destroyed || !isIndex(Uri.parse(url))) { result.cancel(); return true; }
                confirmationResult = result;
                confirmation = new AlertDialog.Builder(MainActivity.this).setTitle("Tunnel").setMessage(message)
                    .setPositiveButton("确定", (dialog, which) -> { confirmationResult = null; result.confirm(); })
                    .setNegativeButton("取消", (dialog, which) -> { confirmationResult = null; result.cancel(); })
                    .setOnCancelListener(dialog -> { confirmationResult = null; result.cancel(); }).create();
                confirmation.show(); return true;
            }
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> result, FileChooserParams parameters) {
                if (!trustedPage || destroyed) { result.onReceiveValue(null); return true; }
                if (fileSelection != null) fileSelection.onReceiveValue(null);
                fileSelection = result;
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);
                try { startActivityForResult(intent, PICK_CONFIG); }
                catch (Exception error) { fileSelection.onReceiveValue(null); fileSelection = null; }
                return true;
            }
        });
        web.setDownloadListener((url, userAgent, disposition, mime, length) -> {});
        setContentView(web);
        trustedPage = true;
        web.loadUrl(ORIGIN + "/index.html");
        if (RuntimeState.pending(pendingStart) && !consentRequested) ui.post(() -> authorize(pendingStart));
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 3);
    }

    private static boolean isIndex(Uri url) {
        return "https".equals(url.getScheme()) && "tunnel.local".equals(url.getHost())
            && url.getPort() == -1 && url.getUserInfo() == null
            && ("/index.html".equals(url.getPath()) || "/".equals(url.getPath()));
    }
    private static WebResourceResponse blocked() {
        return new WebResourceResponse("text/plain", "UTF-8", 403, "Forbidden", new HashMap<>(), new ByteArrayInputStream(new byte[0]));
    }
    private JSONObject readConfig() throws Exception {
        File file = configFile();
        if (!file.exists()) return new JSONObject().put("text", "").put("revision", JSONObject.NULL);
        if (file.length() > 1048576) throw new IllegalArgumentException("配置文件超过 1 MiB");
        byte[] bytes = Files.readAllBytes(file.toPath());
        String configuration = new String(bytes, StandardCharsets.UTF_8);
        String revision = digest(bytes);
        if (configuration.isEmpty()) return new JSONObject().put("text", "").put("revision", revision);
        RuntimeState.rememberSecrets(configuration);
        // Migration is only an in-memory view; invalid text remains repairable and
        // the user's saved file changes only after an explicit Save or Connect.
        try { return new JSONObject().put("text", NativeBridge.normalize(configuration)).put("revision", revision); }
        catch (IllegalStateException error) {
            return new JSONObject().put("text", configuration).put("revision", revision).put("error", RuntimeState.safeError(error.getMessage()));
        }
    }
    private static String digest(byte[] bytes) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder result = new StringBuilder(64);
        for (byte value : hash) result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }
    private JSONObject saveConfig(String configuration, boolean apply, Object expected) throws Exception {
        synchronized (configurationGate) {
            if (expected != null) {
                String current = configFile().exists() ? digest(Files.readAllBytes(configFile().toPath())) : null;
                boolean matches = expected == JSONObject.NULL ? current == null : expected instanceof String && expected.equals(current);
                if (!matches) throw new IllegalStateException("配置已被其他界面修改，请重新载入后再保存");
            }
            String normalized = NativeBridge.normalize(configuration);
            File temporary = new File(getFilesDir(), "configure.json.tmp");
            TunnelService service = apply ? TunnelService.runningService() : null;
            String previous = service == null ? null : service.configuration();
            JSONObject result = new JSONObject();
            // Stage the file before touching the running configuration. Commit
            // it only after TunnelProtocol has confirmed the requested change.
            try {
                Files.write(temporary.toPath(), normalized.getBytes(StandardCharsets.UTF_8));
                if (service != null) result = service.applyConfiguration(normalized);
                try {
                    Files.move(temporary.toPath(), configFile().toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception storageError) {
                    if (service != null) {
                        try { service.applyConfiguration(previous); }
                        catch (Exception rollbackError) {
                            throw new IllegalStateException("保存文件失败，运行配置恢复也失败，请检查当前连接：" + rollbackError.getMessage());
                        }
                    }
                    throw new IllegalStateException("保存文件失败，已保留原配置：" + storageError.getMessage());
                }
            } finally { try { Files.deleteIfExists(temporary.toPath()); } catch (Exception ignored) { /* Preserve the operation's original result. */ } }
            String message = service == null ? "配置已保存，下次连接时生效"
                : result.optBoolean("interrupted", false) ? "已保存并应用配置，受影响的连接正在重新建立" : "已保存并应用配置";
            return result.put("saved", true).put("applied", service != null).put("text", normalized).put("message", message)
                .put("revision", digest(normalized.getBytes(StandardCharsets.UTF_8)));
        }
    }
    private void authorize(long token) {
        if (destroyed || !RuntimeState.pending(token)) return;
        pendingStart = token;
        try {
            Intent consent = VpnService.prepare(this);
            if (consent == null) connect(token);
            else { consentRequested = true; startActivityForResult(consent, VPN_PERMISSION); }
        } catch (Exception error) { RuntimeState.finish(token, "无法申请 VPN 权限：" + error.getMessage()); pendingStart = 0; }
    }
    private void connect(long token) {
        if (!RuntimeState.pending(token)) { pendingStart = 0; return; }
        try {
            startForegroundService(new Intent(this, TunnelService.class).putExtra("generation", token));
        } catch (Exception error) { RuntimeState.finish(token, "无法启动 VPN 服务：" + error.getMessage()); }
        pendingStart = 0;
        consentRequested = false;
    }
    private final class Host {
        @JavascriptInterface public String request(String request) {
            try {
                if (destroyed || !trustedPage) throw new IllegalStateException("界面已关闭");
                if (request == null || request.length() > 2097152) throw new IllegalArgumentException("请求过大");
                JSONObject input = new JSONObject(request);
                String action = input.getString("action");
                JSONObject payload = input.optJSONObject("payload");
                if (payload == null) payload = input; // Accept the desktop host's flat form as well.
                Object suppliedText = payload.opt("text");
                if (suppliedText instanceof String) RuntimeState.rememberSecrets((String) suppliedText);
                Object result;
                switch (action) {
                    case "load_config": result = readConfig(); break;
                    case "normalize_config": result = new JSONObject().put("text", NativeBridge.normalize(payload.getString("text"))); break;
                    case "generate_key": result = new JSONObject().put("key", NativeBridge.generateKey()); break;
                    case "validate_config": result = new JSONObject(NativeBridge.validate(payload.getString("text"))); break;
                    case "save_config":
                    case "reload_config": result = saveConfig(payload.getString("text"), true, payload.opt("expected_sha256")); break;
                    case "start": {
                        String configuration = NativeBridge.normalize(payload.getString("text"));
                        final long token = RuntimeState.begin(configuration);
                        pendingStart = token;
                        JSONObject saved;
                        try { saved = saveConfig(configuration, false, payload.opt("expected_sha256")); }
                        catch (Exception error) { RuntimeState.finish(token, "无法保存启动配置"); throw error; }
                        if (destroyed) { RuntimeState.finish(token, "连接界面已关闭"); throw new IllegalStateException("连接界面已关闭"); }
                        ui.post(() -> authorize(token));
                        result = new JSONObject().put("requested", true).put("revision", saved.get("revision")); break;
                    }
                    case "stop":
                        RuntimeState.requestStop();
                        // Context.stopService is thread-safe; do not queue this on an
                        // Activity Handler that may disappear immediately after Stop.
                        getApplicationContext().stopService(new Intent(getApplicationContext(), TunnelService.class));
                        result = new JSONObject().put("requested", true); break;
                    case "get_state": result = RuntimeState.snapshot(configFile()); break;
                    case "clear_logs": RuntimeState.clearLogs(); result = new JSONObject(); break;
                    case "copy_text": {
                        String copied = payload.getString("text");
                        ui.post(() -> { if (!destroyed) getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("Tunnel", copied)); });
                        result = new JSONObject().put("copied", true); break;
                    }
                    default: throw new IllegalArgumentException("未知操作：" + action);
                }
                return new JSONObject().put("ok", true).put("data", result).toString();
            } catch (Exception error) {
                String message = error instanceof JSONException ? "请求或配置 JSON 格式无效" : RuntimeState.safeError(error.getMessage());
                try { return new JSONObject().put("ok", false).put("error", message).toString(); }
                catch (Exception ignored) { return "{\"ok\":false,\"error\":\"Operation failed\"}"; }
            }
        }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == VPN_PERMISSION) {
            consentRequested = false;
            long token = pendingStart; pendingStart = 0;
            if (!RuntimeState.pending(token)) return;
            if (result == RESULT_OK) connect(token); else RuntimeState.finish(token, "未授予 VPN 权限");
        } else if (request == PICK_CONFIG && fileSelection != null) {
            ValueCallback<Uri[]> selected = fileSelection; fileSelection = null;
            Uri uri = result == RESULT_OK && data != null ? data.getData() : null;
            if (uri != null && !"content".equals(uri.getScheme())) uri = null;
            selected.onReceiveValue(uri == null ? null : new Uri[]{uri});
        }
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        state.putLong("pendingStart", pendingStart); state.putBoolean("consentRequested", consentRequested); super.onSaveInstanceState(state);
    }
    @Override protected void onDestroy() {
        destroyed = true; trustedPage = false; ui.removeCallbacksAndMessages(null);
        if (fileSelection != null) { fileSelection.onReceiveValue(null); fileSelection = null; }
        if (confirmationResult != null) { confirmationResult.cancel(); confirmationResult = null; }
        if (confirmation != null) { confirmation.dismiss(); confirmation = null; }
        if (!isChangingConfigurations() && RuntimeState.pending(pendingStart)) RuntimeState.finish(pendingStart, "连接授权已取消");
        if (web != null) { web.removeJavascriptInterface("TunnelHost"); web.stopLoading(); web.destroy(); web = null; }
        super.onDestroy(); // Closing the Activity deliberately leaves an established VPN running.
    }
}
