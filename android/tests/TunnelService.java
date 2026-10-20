package org.example.tunnel;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** JVM fixture for the real JNI bridge, without an Android VPN or a TUN device. */
public final class TunnelService {
    final ConcurrentHashMap<Long, CompletableFuture<String>> requests = new ConcurrentHashMap<>();
    final CountDownLatch running = new CountDownLatch(1);
    volatile Thread protocol;
    volatile String status;
    volatile Throwable failure;
    volatile CountDownLatch blockStatus, enteredStatus;
    int callbacks;

    private void checkThread() {
        if (Thread.currentThread() != protocol) throw new AssertionError("JNI callback left the protocol thread");
        ++callbacks;
    }
    public boolean protect(int fd) { checkThread(); return true; }
    public int replaceTun(byte[] utf8) { throw new AssertionError("Standalone server must not create a TUN"); }
    public void publishRunning() { checkThread(); running.countDown(); }
    public void publishLog(byte[] utf8) { checkThread(); }
    public void publishStatus(byte[] utf8) {
        checkThread(); status = new String(utf8, StandardCharsets.UTF_8);
        CountDownLatch block = blockStatus;
        if (block != null) {
            enteredStatus.countDown();
            try { if (!block.await(15, TimeUnit.SECONDS)) throw new AssertionError("Test status barrier timed out"); }
            catch (InterruptedException error) { throw new AssertionError(error); }
            blockStatus = null;
        }
    }
    public void publishReload(long request, byte[] utf8) {
        checkThread();
        CompletableFuture<String> completion = requests.remove(request);
        if (completion == null) throw new AssertionError("Unsolicited configuration result");
        completion.complete(new String(utf8, StandardCharsets.UTF_8));
    }
}
