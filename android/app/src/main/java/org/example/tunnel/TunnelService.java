package org.example.tunnel;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.os.Handler;
import android.os.Looper;
import android.system.OsConstants;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.net.InetAddress;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;

public final class TunnelService extends VpnService {
    private static final Object protocolOwner = new Object();
    private static volatile TunnelService activeService;
    private static final AtomicLong reloadSequence = new AtomicLong();
    private final Object gate = new Object();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private long engine, generation;
    private volatile boolean stopping;
    private Thread worker;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback callback;
    private final ConcurrentHashMap<Long, CompletableFuture<JSONObject>> reloads = new ConcurrentHashMap<>();
    private volatile String activeConfiguration;

    private void notification(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("tunnel", "Tunnel VPN", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(this, "tunnel").setContentTitle("Tunnel")
            .setContentText(text).setSmallIcon(android.R.drawable.stat_sys_upload_done).setOngoing(true).setContentIntent(open).build();
        startForeground(1, notification);
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (worker != null) return START_NOT_STICKY;
        long token = intent == null ? 0 : intent.getLongExtra("generation", 0);
        if (!RuntimeState.claim(token)) { stopSelf(startId); return START_NOT_STICKY; }
        generation = token; stopping = false; activeService = this;
        try {
            notification("正在建立加密虚拟网络");
            connectivity = getSystemService(ConnectivityManager.class);
            callback = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { networkChanged(); }
                @Override public void onLost(Network network) { networkChanged(); }
            };
            connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback);
            worker = new Thread(() -> runProtocol(token, startId), "TunnelProtocol");
            worker.start();
        } catch (Exception error) {
            if (activeService == this) activeService = null;
            RuntimeState.finish(token, "无法启动 VPN：" + error.getMessage()); stopSelf(startId);
        }
        return START_NOT_STICKY;
    }
    private void runProtocol(long token, int startId) {
        String failure = "";
        synchronized (protocolOwner) {
            try {
                if (!stopping) {
                    // The exact text approved at Connect survives the permission dialog;
                    // saving a later edit cannot silently change this running session.
                    String configuration = RuntimeState.takeConfiguration(token);
                    activeConfiguration = configuration;
                    // Native creates the first interface only when at least one
                    // static/leased address exists. Allocation TCP can run first.
                    long created = NativeBridge.create(runtimeConfiguration(configuration), -1, this);
                    synchronized (gate) {
                        engine = created;
                        if (stopping) NativeBridge.notify(engine, true);
                    }
                    NativeBridge.run(engine);
                }
            } catch (Exception error) {
                // A stop/revoke arriving while Builder establishes the first
                // interface cancels startup; it is not a failed connection.
                if (!stopping) failure = error.getMessage() == null ? "VPN 运行失败" : error.getMessage();
            } finally {
                synchronized (gate) { if (engine != 0) { NativeBridge.destroy(engine); engine = 0; } }
                failReloads("VPN 已停止，配置未保存");
                if (activeService == this) activeService = null;
            }
        }
        final String result = failure;
        ui.post(() -> {
            worker = null;
            RuntimeState.finish(token, result);
            stopSelfResult(startId);
        });
    }
    private String runtimeConfiguration(String configuration) throws Exception {
        JSONObject document = new JSONObject(configuration);
        JSONObject server = document.optJSONObject("address_server");
        if (server != null) {
            // Apply the same private-directory mapping on initial start and reload.
            String basename = new File(server.optString("state_file", "address-leases.json").replace('\\', '/')).getName();
            if (basename.isEmpty() || basename.equals(".") || basename.equals(".."))
                throw new IllegalArgumentException("地址租约状态文件名无效");
            File stateDirectory = new File(getFilesDir(), "address-state");
            if (!stateDirectory.isDirectory() && !stateDirectory.mkdirs())
                throw new IllegalStateException("无法创建私有地址租约目录");
            server.put("state_file", new File(stateDirectory, basename).getAbsolutePath());
        }
        return document.toString();
    }
    static TunnelService runningService() {
        String phase = RuntimeState.phase();
        if (phase.equals("starting") || phase.equals("stopping"))
            throw new IllegalStateException("VPN 正在启动或停止，请稍后再应用配置");
        if (!phase.equals("running")) return null;
        TunnelService service = activeService;
        if (service == null) throw new IllegalStateException("VPN 正在停止，请稍后重试");
        return service;
    }
    String configuration() { return activeConfiguration; }
    JSONObject applyConfiguration(String configuration) throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper())
            throw new IllegalStateException("配置应用不能阻塞 Android 主线程");
        String runtime = runtimeConfiguration(configuration);
        long request = reloadSequence.incrementAndGet();
        CompletableFuture<JSONObject> completion = new CompletableFuture<>();
        synchronized (gate) {
            if (stopping || engine == 0 || !RuntimeState.phase().equals("running"))
                throw new IllegalStateException("VPN 未运行，配置未保存");
            reloads.put(request, completion);
            try { NativeBridge.reload(engine, request, runtime); }
            catch (Exception error) { reloads.remove(request); throw error; }
        }
        // Never hold gate while waiting: stop/revoke and protocol teardown must
        // remain able to reject requests. No timeout can report failure while a
        // still-queued configuration later silently commits.
        boolean interrupted = false;
        try {
            JSONObject result;
            for (;;) {
                try { result = completion.get(); break; }
                catch (InterruptedException ignored) { interrupted = true; }
                catch (ExecutionException error) { throw new IllegalStateException(error.getCause().getMessage()); }
            }
            if (!result.optBoolean("ok", false)) {
                String message = result.optString("error", "配置应用失败");
                if (result.has("rollback_error")) message += "；恢复原配置失败：" + result.optString("rollback_error");
                throw new IllegalStateException(message);
            }
            activeConfiguration = configuration;
            return result;
        } finally { if (interrupted) Thread.currentThread().interrupt(); }
    }
    public void publishReload(long request, byte[] utf8) {
        CompletableFuture<JSONObject> completion = reloads.remove(request);
        if (completion == null) return;
        try { completion.complete(new JSONObject(new String(utf8, StandardCharsets.UTF_8))); }
        catch (Exception error) { completion.completeExceptionally(error); }
    }
    private void failReloads(String message) {
        for (Long request : reloads.keySet()) {
            CompletableFuture<JSONObject> completion = reloads.remove(request);
            if (completion != null) completion.completeExceptionally(new IllegalStateException(message));
        }
    }
    // JNI invokes these only on TunnelProtocol. Publish detached JSON, never Node pointers.
    public int replaceTun(byte[] utf8) throws Exception {
        JSONObject specification = new JSONObject(new String(utf8, StandardCharsets.UTF_8));
        JSONArray networks = specification.getJSONArray("networks");
        if (networks.length() == 0) return -1; // Native closes the previous owned fd.
        if (stopping) throw new IllegalStateException("VPN 正在停止");
        Builder builder = new Builder().setSession("Tunnel").setMtu(specification.getInt("mtu")).setBlocking(false)
            .allowFamily(OsConstants.AF_INET).allowFamily(OsConstants.AF_INET6);
        for (int i = 0; i < networks.length(); ++i) {
            JSONObject network = networks.getJSONObject(i);
            builder.addAddress(network.getString("address"), network.getInt("prefix"));
            builder.addRoute(network.getString("network"), network.getInt("prefix"));
        }
        JSONArray routes = specification.optJSONArray("routes");
        if (routes != null) for (int i = 0; i < routes.length(); ++i) {
            JSONObject route = routes.getJSONObject(i);
            String address = route.getString("network");
            int prefix = route.getInt("prefix");
            checkImportedRoute(InetAddress.getByName(address), prefix);
            builder.addRoute(address, prefix);
        }
        // Android changes VPN addresses by establishing a replacement interface.
        // Return its fd to the same protocol thread, which swaps registrations
        // and closes the previous fd without recreating Node or its peer sockets.
        try (ParcelFileDescriptor tun = builder.establish()) {
            if (tun == null) throw new IllegalStateException("VPN 授权已撤销");
            return tun.detachFd();
        }
    }
    private static boolean prefixesOverlap(byte[] left, int leftBits, byte[] right, int rightBits) {
        if (left.length != right.length) return false;
        int bits = Math.min(leftBits, rightBits);
        for (int i = 0; i < bits; ++i) {
            int mask = 1 << (7 - i % 8);
            if ((left[i / 8] & mask) != (right[i / 8] & mask)) return false;
        }
        return true;
    }
    private void checkImportedRoute(InetAddress address, int prefix) {
        if (prefix <= 0 || prefix > address.getAddress().length * 8)
            throw new IllegalArgumentException("导入子网前缀无效");
        if (connectivity == null) throw new IllegalStateException("无法检查底层网络路由");
        for (Network network : connectivity.getAllNetworks()) {
            NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
            if (capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
            LinkProperties properties = connectivity.getLinkProperties(network);
            if (properties == null) continue;
            for (LinkAddress local : properties.getLinkAddresses())
                if (prefixesOverlap(address.getAddress(), prefix, local.getAddress().getAddress(), local.getPrefixLength()))
                    throw new IllegalArgumentException("导入子网与底层网络地址重叠");
        }
    }
    public void publishStatus(byte[] utf8) { RuntimeState.publish(generation, utf8); }
    public void publishLog(byte[] utf8) { RuntimeState.log(generation, "info", new String(utf8, StandardCharsets.UTF_8)); }
    public void publishRunning() {
        RuntimeState.running(generation);
        ui.post(() -> { if (!stopping) notification("隧道运行中，正在维护节点连接"); });
    }
    private void networkChanged() {
        synchronized (gate) { if (engine != 0 && !stopping) NativeBridge.notify(engine, false); }
    }
    private void requestStop() {
        synchronized (gate) {
            stopping = true;
            RuntimeState.requestStop(generation);
            if (engine != 0) NativeBridge.notify(engine, true);
        }
    }
    @Override public void onRevoke() { requestStop(); stopSelf(); }
    @Override public void onDestroy() {
        requestStop();
        if (callback != null && connectivity != null) {
            try { connectivity.unregisterNetworkCallback(callback); } catch (IllegalArgumentException ignored) {}
            callback = null;
        }
        stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy();
    }
}
