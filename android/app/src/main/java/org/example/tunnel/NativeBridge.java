package org.example.tunnel;
import java.nio.charset.StandardCharsets;
final class NativeBridge {
    static { System.loadLibrary("tunnel_android"); }
    static String validate(String config) { return validateBytes(config.getBytes(StandardCharsets.UTF_8)); }
    static String normalize(String config) { return new String(normalizeBytes(config.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8); }
    static long create(String config, int tunFd, TunnelService service) { return createBytes(config.getBytes(StandardCharsets.UTF_8), tunFd, service); }
    static void reload(long handle, long request, String config) { reloadBytes(handle, request, config.getBytes(StandardCharsets.UTF_8)); }
    private static native String validateBytes(byte[] config);
    private static native byte[] normalizeBytes(byte[] config);
    private static native long createBytes(byte[] config, int tunFd, TunnelService service);
    private static native void reloadBytes(long handle, long request, byte[] config);
    static native String generateKey();
    static native void run(long handle);
    static native void notify(long handle, boolean stop);
    static native void destroy(long handle);
    private NativeBridge() {}
}
