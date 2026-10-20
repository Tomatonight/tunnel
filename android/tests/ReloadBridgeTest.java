package org.example.tunnel;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exercises the production android/jni.cpp against a real core and JVM. */
public final class ReloadBridgeTest {
    private static int assertions;
    private static void check(boolean condition, String message) {
        ++assertions;
        if (!condition) throw new AssertionError(message);
    }
    private static String config(int port, Path state, int reclaim, String key) {
        return "{\"address_server\":{\"address\":\"127.0.0.1:" + port + "\",\"state_file\":\"" + state
            + "\",\"shared_key\":\"" + key + "\",\"networks\":[\"10.253.249.0/24\"],\"reclaim_after\":" + reclaim + "}}";
    }
    private static String key(String status) {
        Matcher value = Pattern.compile("\\\"public_key\\\":\\\"([0-9a-f]+)\\\"").matcher(status);
        if (!value.find()) throw new AssertionError("Missing node identity");
        return value.group(1);
    }
    private static CompletableFuture<String> enqueue(TunnelService service, long handle, long id, String config) {
        CompletableFuture<String> completion = new CompletableFuture<>();
        service.requests.put(id, completion);
        try { NativeBridge.reload(handle, id, config); }
        catch (RuntimeException error) { service.requests.remove(id); throw error; }
        return completion;
    }
    private static String reload(TunnelService service, long handle, long id, String config) throws Exception {
        return enqueue(service, handle, id, config).get(15, TimeUnit.SECONDS);
    }
    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("tunnel-android-jni-");
        TunnelService service = new TunnelService();
        AtomicLong handle = new AtomicLong();
        Object lifecycle = new Object();
        int port;
        try (ServerSocket reserve = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) { port = reserve.getLocalPort(); }
        String initial = config(port, directory.resolve("leases.json"), 3600, "disposable-jni-test-key");
        Thread worker = new Thread(() -> {
            service.protocol = Thread.currentThread();
            try {
                long created = NativeBridge.create(initial, -1, service);
                synchronized (lifecycle) { handle.set(created); }
                NativeBridge.run(created);
            } catch (Throwable error) { service.failure = error; service.running.countDown(); }
            finally {
                synchronized (lifecycle) {
                    long owned = handle.getAndSet(0);
                    if (owned != 0) NativeBridge.destroy(owned);
                }
            }
        }, "JNI-Test-Protocol");
        worker.start();
        try {
            check(service.running.await(15, TimeUnit.SECONDS), "Core startup timed out");
            check(service.failure == null, "Core startup failed: " + service.failure);
            long engine = handle.get();
            for (int i = 0; service.status == null && i < 100; ++i) Thread.sleep(10);
            check(service.status != null, "Missing initial status");
            String identity = key(service.status);
            String result = reload(service, engine, 1, initial);
            check(result.contains("\"ok\":true") && result.contains("\"mode\":\"noop\""), "No-op reload failed: " + result);
            result = reload(service, engine, 2, "{invalid");
            check(result.contains("\"ok\":false"), "Malformed configuration accepted");
            result = reload(service, engine, 3, initial);
            check(result.contains("\"mode\":\"noop\""), "Invalid input changed running configuration");
            String changed = config(port, directory.resolve("leases.json"), 7200, "disposable-jni-test-key");
            result = reload(service, engine, 4, changed);
            check(result.contains("\"ok\":true") && result.contains("\"mode\":\"rebuild\""), "Resource reload failed: " + result);
            // Wait for the next snapshot, which follows the result callback.
            Thread.sleep(600);
            check(identity.equals(key(service.status)), "Resource reload changed process identity");
            try (ServerSocket occupied = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
                result = reload(service, engine, 5, config(occupied.getLocalPort(), directory.resolve("leases.json"), 7200, "disposable-jni-test-key"));
                check(result.contains("\"ok\":false") && result.contains("\"rolled_back\":true") && result.contains("\"running\":true"),
                    "Failed resource reload did not restore old service: " + result);
            }
            result = reload(service, engine, 6, changed);
            check(result.contains("\"mode\":\"noop\""), "Rollback did not restore old configuration");
            String unicode = config(port, directory.resolve("leases.json"), 7200, "测试独立预共享密钥-1234567890");
            check(NativeBridge.normalize(unicode).contains("测试独立预共享密钥"), "JNI normalization corrupted UTF-8");
            result = reload(service, engine, 7, unicode);
            check(result.contains("\"ok\":true"), "UTF-8 configuration reload failed");

            service.enteredStatus = new CountDownLatch(1);
            service.blockStatus = new CountDownLatch(1);
            check(service.enteredStatus.await(5, TimeUnit.SECONDS), "Could not synchronize pending-request test");
            List<CompletableFuture<String>> pending = new ArrayList<>();
            for (int i = 0; i < 8; ++i) pending.add(enqueue(service, engine, 20 + i, unicode));
            boolean bounded = false;
            try { enqueue(service, engine, 40, unicode); } catch (IllegalStateException expected) { bounded = true; }
            check(bounded, "Reload queue was not bounded");
            NativeBridge.notify(engine, true);
            service.blockStatus.countDown();
            for (CompletableFuture<String> completion : pending)
                check(completion.get(5, TimeUnit.SECONDS).contains("\"ok\":false"), "Stop did not reject queued reload");
            worker.join(5000);
            check(!worker.isAlive(), "Protocol thread did not stop");
            check(service.failure == null, "Protocol worker failed: " + service.failure);
            check(service.callbacks > 10, "Expected actual protocol-thread callbacks");
            System.out.println("Android JNI host reload: " + assertions + " assertions passed");
        } finally {
            CountDownLatch block = service.blockStatus;
            if (block != null) block.countDown();
            synchronized (lifecycle) { if (handle.get() != 0) NativeBridge.notify(handle.get(), true); }
            worker.join(5000);
            try (java.util.stream.Stream<Path> paths = Files.walk(directory)) {
                for (Path path : (Iterable<Path>) paths.sorted(Comparator.reverseOrder())::iterator) Files.deleteIfExists(path);
            }
        }
    }
}
