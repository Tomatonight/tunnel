#include "node.h"
#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <csignal>
#include <atomic>
#include <cerrno>
#include <deque>
#include <mutex>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace {
std::string text(JNIEnv* env, jbyteArray value) {
    if (!value) throw std::invalid_argument("missing configuration");
    const auto size = env->GetArrayLength(value);
    if (size > 1048576) throw std::invalid_argument("configuration exceeds 1 MiB");
    std::string result(static_cast<std::size_t>(size), '\0');
    if (size) env->GetByteArrayRegion(value, 0, size, reinterpret_cast<jbyte*>(&result[0]));
    if (env->ExceptionCheck()) throw std::runtime_error("configuration copy failed");
    return result; // Standard UTF-8, including non-ASCII PSKs, matches desktop JSON.
}
void report(JNIEnv* env, const std::exception& e) { env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), e.what()); }
Configure android_config(const std::string& value) {
    auto config = parse_config(value);
    if (!config.advertise_routes.empty())
        throw std::invalid_argument("Android supports subnet access only; configure subnet publishing on a desktop gateway");
    return config;
}
struct Engine {
    EventLoop loop;
    std::unique_ptr<Node> node;
    EventLoop::Handle control, status_timer;
    int pipe[2]{-1, -1};
    JNIEnv* env;
    jobject service = nullptr;
    jmethodID status_method = nullptr, log_method = nullptr, running_method = nullptr, network_method = nullptr, reload_method = nullptr;
    std::atomic<bool> stopping{false};
    struct Reload { jlong request; std::string configuration; };
    std::mutex reload_mutex;
    std::deque<Reload> reloads;
    std::string fatal_error;
    Engine(JNIEnv* e, jobject s, const Configure& config, int& tun) : env(e) {
        service = env->NewGlobalRef(s);
        try {
            if (!service || pipe2(pipe, O_NONBLOCK | O_CLOEXEC) < 0) throw std::runtime_error("Android control pipe allocation");
            auto klass = env->GetObjectClass(service);
            const auto protect = env->GetMethodID(klass, "protect", "(I)Z");
            status_method = env->GetMethodID(klass, "publishStatus", "([B)V");
            log_method = env->GetMethodID(klass, "publishLog", "([B)V");
            running_method = env->GetMethodID(klass, "publishRunning", "()V");
            network_method = env->GetMethodID(klass, "replaceTun", "([B)I");
            reload_method = env->GetMethodID(klass, "publishReload", "(J[B)V");
            env->DeleteLocalRef(klass);
            if (!protect || !status_method || !log_method || !running_method || !network_method || !reload_method) throw std::runtime_error("VpnService bridge unavailable");
            NodeOptions options;
            static const auto process_identity = std::make_shared<IdentityKey>();
            options.identity = process_identity;
            options.protect = [this, protect](evutil_socket_t fd) {
                const auto ok = env->CallBooleanMethod(service, protect, static_cast<jint>(fd));
                if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
                return ok == JNI_TRUE;
            };
            options.log = [this](const std::string& line) {
                try { publish(log_method, line); } catch (...) { /* Logging must not unwind Node shutdown. */ }
            };
            const auto owned = tun; tun = -1;
            options.device_factory = [this](const Configure& next) { return make_device(next, -1); };
            auto device = make_device(config, owned);
            node.reset(new Node(loop, config, std::move(device), options));
            control = loop.addRead(pipe[0], [this](evutil_socket_t, short) {
                char commands[128]; const auto size = read(pipe[0], commands, sizeof(commands));
                bool stop = stopping.load(std::memory_order_relaxed), reset = false;
                for (ssize_t i = 0; i < size; ++i) { stop |= commands[i] == 'S'; reset |= commands[i] == 'R'; }
                if (stop) { reject_reloads("VPN is stopping"); node->stop(); loop.breakLoop(); }
                else {
                    // Node and TUN mutations are confined to TunnelProtocol. A
                    // Java caller only appends text and wakes this control pipe.
                    std::deque<Reload> pending;
                    { std::lock_guard<std::mutex> lock(reload_mutex); pending.swap(reloads); }
                    for (const auto& request : pending) {
                        wire::Json result;
                        try {
                            if (stopping.load(std::memory_order_relaxed)) throw std::runtime_error("VPN is stopping");
                            result = node->apply_config(android_config(request.configuration));
                        }
                        catch (const std::exception& error) { result = {{"ok", false}, {"error", error.what()}}; }
                        publish_reload(request.request, result.dump());
                        if (!result.value("ok", false) && !result.value("running", true)) {
                            fatal_error = result.value("error", "configuration reload failed") + std::string("; rollback failed: ")
                                + result.value("rollback_error", "unknown error");
                            stopping.store(true, std::memory_order_relaxed);
                        }
                    }
                    if (!fatal_error.empty()) { reject_reloads(fatal_error); node->stop(); loop.breakLoop(); return; }
                    if (reset) node->reset_links();
                    publish(status_method, node->status().dump());
                }
            });
            status_timer = loop.addTimer(std::chrono::milliseconds(500), [this](evutil_socket_t, short) {
                publish(status_method, node->status().dump());
            }, true);
            if (!control || !status_timer) throw std::runtime_error("Android event registration failed");
        } catch (...) { cleanup(); throw; }
    }
    std::unique_ptr<PacketDevice> make_device(const Configure& config, int owned) {
        if (config.networks.empty()) {
            if (owned >= 0) close(owned); // A standalone address server has no TUN.
            return {};
        }
        // Each replacement captures the new configuration's MTU, including the
        // later lease/route updates that rebuild Android's VPN interface.
        const auto mtu = config.tun_mtu;
        return open_tun(loop, config, "", owned, {}, [this, mtu](const std::vector<NetworkConfig>& networks, const std::vector<ImportedRoute>& routes) {
                    wire::Json entries = wire::Json::array();
                    for (const auto& n : networks) entries.push_back({{"address", n.tunnel_ip.str()},
                        {"network", n.tunnel.address.str()}, {"prefix", n.tunnel.prefix}});
                    wire::Json imported = wire::Json::array();
                    for (const auto& r : routes) imported.push_back({{"network", r.prefix.address.str()}, {"prefix", r.prefix.prefix}});
                    const auto value = wire::Json{{"mtu", mtu}, {"networks", entries}, {"routes", imported}}.dump();
                    const auto bytes = env->NewByteArray(static_cast<jsize>(value.size()));
                    jint descriptor = -1;
                    if (bytes) {
                        env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(value.size()), reinterpret_cast<const jbyte*>(value.data()));
                        if (!env->ExceptionCheck()) descriptor = env->CallIntMethod(service, network_method, bytes);
                        env->DeleteLocalRef(bytes);
                    }
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                        if (descriptor >= 0) close(descriptor);
                        throw std::runtime_error("Android VpnService address/route update failed; TUN closed");
                    }
                    return static_cast<int>(descriptor);
        });
    }
    void enqueue_reload(jlong request, std::string configuration) {
        {
            std::lock_guard<std::mutex> lock(reload_mutex);
            if (stopping.load(std::memory_order_relaxed)) throw std::runtime_error("VPN is stopping");
            if (reloads.size() >= 8) throw std::runtime_error("too many pending configuration changes");
            reloads.push_back({request, std::move(configuration)});
        }
        const char command = 'C';
        while (write(pipe[1], &command, 1) < 0 && errno == EINTR) {}
        // EAGAIN is safe: any pending pipe notification drains the reload queue.
    }
    void publish_reload(jlong request, const std::string& value) {
        const auto data = env->NewByteArray(static_cast<jsize>(value.size()));
        if (data) {
            env->SetByteArrayRegion(data, 0, static_cast<jsize>(value.size()), reinterpret_cast<const jbyte*>(value.data()));
            if (!env->ExceptionCheck()) env->CallVoidMethod(service, reload_method, request, data);
            env->DeleteLocalRef(data);
        }
        if (env->ExceptionCheck()) { env->ExceptionClear(); throw std::runtime_error("Android configuration result publication failed"); }
    }
    void reject_reloads(const std::string& error) {
        std::deque<Reload> pending;
        { std::lock_guard<std::mutex> lock(reload_mutex); pending.swap(reloads); }
        const auto result = wire::Json{{"ok", false}, {"error", error}}.dump();
        for (const auto& request : pending) publish_reload(request.request, result);
    }
    void publish(jmethodID method, const std::string& value) {
        // Use standard UTF-8 bytes, not JNI modified UTF-8. This callback runs on
        // the same protocol thread as Node and never calls back into its state.
        const auto data = env->NewByteArray(static_cast<jsize>(value.size()));
        if (data) {
            env->SetByteArrayRegion(data, 0, static_cast<jsize>(value.size()), reinterpret_cast<const jbyte*>(value.data()));
            if (!env->ExceptionCheck()) env->CallVoidMethod(service, method, data);
            env->DeleteLocalRef(data);
        }
        if (env->ExceptionCheck()) { env->ExceptionClear(); throw std::runtime_error("Android state publication failed"); }
    }
    void run() {
        node->start();
        env->CallVoidMethod(service, running_method);
        if (env->ExceptionCheck()) { env->ExceptionClear(); throw std::runtime_error("Android startup publication failed"); }
        publish(status_method, node->status().dump());
        loop.run(); node->stop();
        if (!fatal_error.empty()) throw std::runtime_error(fatal_error);
    }
    void cleanup() {
        status_timer.reset(); control.reset(); node.reset();
        for (auto fd : pipe) if (fd >= 0) close(fd);
        pipe[0] = pipe[1] = -1;
        if (service) { env->DeleteGlobalRef(service); service = nullptr; }
    }
    ~Engine() { cleanup(); }
};
}
extern "C" JNIEXPORT jstring JNICALL Java_org_example_tunnel_NativeBridge_validateBytes(JNIEnv* env, jclass, jbyteArray json) {
    try {
        const auto c = android_config(text(env, json)); wire::Json networks = wire::Json::array();
        for (const auto& n : c.networks) if (!n.tunnel_ip.unspecified())
            networks.push_back({{"address", n.tunnel_ip.str()}, {"network", n.tunnel.address.str()}, {"prefix", n.tunnel.prefix}});
        const auto result = wire::Json{{"mtu", c.tun_mtu}, {"networks", networks}}.dump();
        return env->NewStringUTF(result.c_str());
    } catch (const std::exception& e) { report(env, e); return nullptr; }
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_example_tunnel_NativeBridge_normalizeBytes(JNIEnv* env, jclass, jbyteArray json) {
    try {
        const auto result = serialize_config(android_config(text(env, json)));
        if (result.size() > 1048576) throw std::invalid_argument("normalized configuration exceeds 1 MiB");
        const auto output = env->NewByteArray(static_cast<jsize>(result.size()));
        if (output && !result.empty())
            env->SetByteArrayRegion(output, 0, static_cast<jsize>(result.size()), reinterpret_cast<const jbyte*>(result.data()));
        return output;
    } catch (const std::exception& e) { report(env, e); return nullptr; }
}
extern "C" JNIEXPORT jstring JNICALL Java_org_example_tunnel_NativeBridge_generateKey(JNIEnv* env, jclass) {
    try {
        Secret key{};
        if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
            OPENSSL_cleanse(key.data(), key.size());
            throw std::runtime_error("secure key generation failed");
        }
        std::string encoded;
        try { encoded = wire::hex(key); }
        catch (...) { OPENSSL_cleanse(key.data(), key.size()); throw; }
        OPENSSL_cleanse(key.data(), key.size());
        const auto output = env->NewStringUTF(encoded.c_str()); // Hex is ASCII.
        OPENSSL_cleanse(&encoded[0], encoded.size());
        return output;
    } catch (const std::exception& e) { report(env, e); return nullptr; }
}
extern "C" JNIEXPORT jlong JNICALL Java_org_example_tunnel_NativeBridge_createBytes(JNIEnv* env, jclass, jbyteArray json, jint fd, jobject service) {
    int descriptor = fd;
    try {
        auto c = android_config(text(env, json));
        return reinterpret_cast<jlong>(new Engine(env, service, c, descriptor));
    } catch (const std::exception& e) { if (descriptor >= 0) close(descriptor); report(env, e); return 0; }
}
extern "C" JNIEXPORT void JNICALL Java_org_example_tunnel_NativeBridge_run(JNIEnv* env, jclass, jlong handle) {
    try {
        std::signal(SIGPIPE, SIG_IGN);
        auto* engine = reinterpret_cast<Engine*>(handle); engine->run();
    } catch (const std::exception& e) { report(env, e); }
}
extern "C" JNIEXPORT void JNICALL Java_org_example_tunnel_NativeBridge_notify(JNIEnv*, jclass, jlong handle, jboolean stop) {
    auto* engine = reinterpret_cast<Engine*>(handle); const char command = stop ? 'S' : 'R';
    // Java serializes notify/destroy. Only this pipe crosses threads.
    if (stop) engine->stopping.store(true, std::memory_order_relaxed);
    while (write(engine->pipe[1], &command, 1) < 0 && errno == EINTR) {}
    // EAGAIN means a wakeup is already pending; the atomic stop flag cannot be lost.
}
extern "C" JNIEXPORT void JNICALL Java_org_example_tunnel_NativeBridge_reloadBytes(JNIEnv* env, jclass, jlong handle, jlong request, jbyteArray json) {
    try { reinterpret_cast<Engine*>(handle)->enqueue_reload(request, text(env, json)); }
    catch (const std::exception& error) { report(env, error); }
}
extern "C" JNIEXPORT void JNICALL Java_org_example_tunnel_NativeBridge_destroy(JNIEnv*, jclass, jlong handle) {
    delete reinterpret_cast<Engine*>(handle);
}
