package org.example.tunnel;

import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;

/** UI-readable copies only; the native Node always stays on its protocol thread. */
final class RuntimeState {
    private static final Object lock = new Object();
    private static final ArrayDeque<JSONObject> logs = new ArrayDeque<>();
    private static final ArrayList<String> secrets = new ArrayList<>();
    private static String phase = "stopped", error = "";
    private static JSONObject status = new JSONObject();
    private static long generation, logId;
    private static long lastStatusElapsed;
    private static boolean claimed;
    private static String startupConfiguration;

    static long begin(String configuration) throws Exception {
        synchronized (lock) {
            if (!phase.equals("stopped") && !phase.equals("error"))
                throw new IllegalStateException("请先断开当前连接，等待停止后再连接");
            rememberSecrets(configuration);
            ++generation; claimed = false; phase = "starting"; error = ""; status = new JSONObject();
            lastStatusElapsed = 0;
            startupConfiguration = configuration;
            logLocked("info", "正在申请 VPN 权限并启动隧道");
            return generation;
        }
    }
    static boolean pending(long token) {
        synchronized (lock) { return token == generation && phase.equals("starting") && !claimed; }
    }
    static String phase() { synchronized (lock) { return phase; } }
    static boolean claim(long token) {
        synchronized (lock) {
            if (!pending(token)) return false;
            claimed = true; return true;
        }
    }
    static String takeConfiguration(long token) {
        synchronized (lock) {
            if (token != generation || startupConfiguration == null) throw new IllegalStateException("启动配置已取消");
            String result = startupConfiguration; startupConfiguration = null; return result;
        }
    }
    static void running(long token) {
        synchronized (lock) {
            if (token != generation || !phase.equals("starting")) return;
            phase = "running"; logLocked("info", "隧道已运行，正在维护节点连接");
        }
    }
    static void publish(long token, byte[] data) {
        synchronized (lock) {
            if (token != generation) return;
            try {
                status = new JSONObject(new String(data, StandardCharsets.UTF_8));
                lastStatusElapsed = SystemClock.elapsedRealtime();
            }
            catch (Exception ignored) { logLocked("error", "无法读取协议状态快照"); }
        }
    }
    static void log(long token, String level, String message) {
        synchronized (lock) { if (token == generation) logLocked(level, message); }
    }
    static void requestStop() {
        synchronized (lock) {
            requestStop(generation);
        }
    }
    static void requestStop(long token) {
        synchronized (lock) {
            if (token != generation) return;
            if (phase.equals("stopped") || phase.equals("error")) return;
            if (!claimed) { phase = "stopped"; startupConfiguration = null; logLocked("info", "已取消连接"); }
            else { phase = "stopping"; logLocked("info", "正在停止隧道"); }
        }
    }
    static void finish(long token, String failure) {
        synchronized (lock) {
            if (token != generation) return;
            error = redact(failure == null ? "" : failure);
            phase = error.isEmpty() ? "stopped" : "error"; claimed = false;
            startupConfiguration = null;
            status = new JSONObject();
            lastStatusElapsed = 0;
            logLocked(error.isEmpty() ? "info" : "error", error.isEmpty() ? "隧道已停止" : error);
        }
    }
    static JSONObject snapshot(File config) throws Exception {
        synchronized (lock) {
            JSONArray copied = new JSONArray(); for (JSONObject entry : logs) copied.put(entry);
            boolean active = phase.equals("starting") || phase.equals("running") || phase.equals("stopping");
            boolean stale = active && lastStatusElapsed != 0 && SystemClock.elapsedRealtime() - lastStatusElapsed > 3000;
            return new JSONObject().put("phase", phase).put("error", error).put("status", status)
                .put("logs", copied).put("config_path", config.getAbsolutePath()).put("platform", "Android")
                .put("status_stale", stale);
        }
    }
    static void clearLogs() { synchronized (lock) { logs.clear(); } }
    static void rememberSecrets(String configuration) {
        synchronized (lock) {
            // Collect only to redact errors; the native parser remains authoritative.
            // Retain the previous run's keys while a new configuration is being edited.
            try {
                JSONObject document = new JSONObject(configuration);
                rememberKeys(document.optJSONArray("peers"));
                rememberKeys(document.optJSONArray("address_clients"));
                JSONObject server = document.optJSONObject("address_server");
                if (server != null) {
                    rememberKey(server);
                    rememberKeys(server.optJSONArray("clients"));
                }
                while (secrets.size() > 4096) secrets.remove(0);
            } catch (Exception ignored) { /* Never echo malformed JSON fragments. */ }
        }
    }
    private static void rememberKeys(JSONArray entries) {
        if (entries == null) return;
        for (int i = 0; i < Math.min(entries.length(), 1024); ++i) rememberKey(entries.optJSONObject(i));
    }
    private static void rememberKey(JSONObject entry) {
        Object value = entry == null ? null : entry.opt("shared_key");
        if (!(value instanceof String) || ((String) value).isEmpty()) return;
        String key = (String) value;
        if (!secrets.contains(key)) secrets.add(key);
    }
    static String safeError(String message) { synchronized (lock) { return redact(message == null ? "操作失败" : message); } }
    private static String redact(String message) {
        for (String secret : secrets) {
            message = message.replace(secret, "[redacted]");
            String quoted = JSONObject.quote(secret);
            message = message.replace(quoted.substring(1, quoted.length() - 1), "[redacted]");
        }
        return message.length() <= 2048 ? message : message.substring(0, 2048) + "…";
    }
    private static void logLocked(String level, String message) {
        try {
            JSONObject row = new JSONObject().put("id", ++logId).put("time", System.currentTimeMillis())
                .put("level", level).put("message", redact(message));
            logs.addLast(row); while (logs.size() > 256) logs.removeFirst();
        } catch (Exception ignored) { /* Logging must not interrupt shutdown. */ }
    }
    private RuntimeState() {}
}
