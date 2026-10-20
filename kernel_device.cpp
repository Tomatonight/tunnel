#include "kernel_device.h"
#include "subnet_platform.h"
#include <algorithm>
#include <cstring>
#include <openssl/crypto.h>
#if defined(__linux__) && !defined(__ANDROID__)
#include "kernel/tunnel_uapi.h"
#include <cerrno>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void run_ip(const std::vector<std::string>& arguments) {
    std::vector<char*> argv; for (const auto& a : arguments) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    const auto pid = fork();
    if (pid < 0) throw std::runtime_error("cannot start iproute2");
    if (!pid) { execvp(argv[0], argv.data()); _exit(127); }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) throw std::runtime_error("waitpid(iproute2) failed");
    if (!WIFEXITED(status) || WEXITSTATUS(status)) throw std::runtime_error("kernel interface configuration failed");
}
tnlk_ip native_ip(const IpAddress& a) {
    tnlk_ip r{}; r.family = static_cast<__u8>(a.family); std::copy(a.bytes.begin(), a.bytes.end(), r.bytes); return r;
}
tnlk_endpoint native_endpoint(const Endpoint& a) { tnlk_endpoint r{}; r.ip = native_ip(a.ip); r.port = a.port; return r; }
tnlk_network native_network(const Network& a) { tnlk_network r{}; r.address = native_ip(a.address); r.prefix = static_cast<__u8>(a.prefix); return r; }
IpAddress from_ip(const tnlk_ip& a) { IpAddress r; r.family = a.family; std::copy(a.bytes, a.bytes + 16, r.bytes.begin()); return r; }
Endpoint from_endpoint(const tnlk_endpoint& a) { Endpoint r; r.ip = from_ip(a.ip); r.port = a.port; return r; }
Network from_network(const tnlk_network& a) { Network r; r.address = from_ip(a.address); r.prefix = a.prefix; return r; }
void native_keys(tnlk_keys& out, const CryptoSession& session) {
    std::copy(session.id().begin(), session.id().end(), out.id);
    std::copy(session.offload_keys().send.begin(), session.offload_keys().send.end(), out.send);
    std::copy(session.offload_keys().receive.begin(), session.offload_keys().receive.end(), out.receive);
}
struct SecretBytes : Bytes { ~SecretBytes() { if (!empty()) OPENSSL_cleanse(data(), size()); } };
template<class T> void append(Bytes& b, const T& item) {
    const auto* start = reinterpret_cast<const unsigned char*>(&item); b.insert(b.end(), start, start + sizeof(item));
}
class KernelDevice final : public PacketDevice, public KernelDataPlane {
public:
    KernelDevice(EventLoop& loop, const Configure& config, const std::string& name) : config_(config) {
        if (name.size() >= 16) throw std::invalid_argument("kernel interface name is too long");
        for (char c : name) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            throw std::invalid_argument("invalid kernel interface name");
        fd_ = open("/dev/tunnel_kmod", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd_ < 0) throw std::runtime_error("cannot open /dev/tunnel_kmod: load tunnel_kmod.ko and run with CAP_NET_ADMIN (" + std::string(std::strerror(errno)) + ")");
        try {
            tnlk_create create{}; create.abi = TNLK_ABI; create.mtu = config.tun_mtu;
            create.transport_mtu = config.transport_mtu; create.lease_ms = 20000;
            create.local = native_endpoint(config.listen.address); create.bind = native_endpoint(config.listen.bind_address);
            std::memcpy(create.name, name.c_str(), name.size());
            checked(TNLK_CREATE, &create, "create");
            name_.assign(create.name, strnlen(create.name, sizeof(create.name)));
            if (name_.empty() || name_.size() >= sizeof(create.name)) throw std::runtime_error("kernel returned invalid interface name");
            platform_.reset(new SubnetPlatform(name_, config));
            run_ip({"ip", "link", "set", "dev", name_, "mtu", std::to_string(config.tun_mtu), "up"});
            set_networks(config.networks);
            read_ = loop.addRead(fd_, [this](evutil_socket_t, short) { read_events(); });
            if (!read_) throw std::runtime_error("kernel event registration failed");
            read_->del();
        } catch (...) { close_device(); throw; }
    }
    ~KernelDevice() override { close_device(); }
    std::string name() const override { return name_; }
    bool healthy() const override { return !failed_ && fd_ >= 0; }
    bool send(const Bytes&) override { return false; } // No raw-IP userspace path.
    void start(Receiver receiver) override {
        if (!healthy()) { if (receiver) throw std::runtime_error("kernel interface is closed"); return; }
        if (receiver) read_->add();
        else { read_->del(); update(KernelState{}); }
    }
    void on_event(std::function<void(KernelEvent)> cb) override { event_ = std::move(cb); }
    void set_networks(const std::vector<NetworkConfig>& requested) override {
        std::vector<NetworkConfig> next;
        for (const auto& n : requested) {
            if (n.tunnel_ip.unspecified() && n.allocation_server.port) continue;
            if (!n.tunnel.usable_host(n.tunnel_ip)) throw std::invalid_argument("invalid kernel interface IP");
            next.push_back(n);
        }
        auto contains = [](const std::vector<NetworkConfig>& list, const NetworkConfig& n) {
            for (const auto& old : list) if (old.tunnel == n.tunnel && old.tunnel_ip == n.tunnel_ip) return true;
            return false;
        };
        try {
            std::vector<ImportedRoute> kept;
            for (const auto& r : imports_) for (const auto& n : next) if (r.tunnel == n.tunnel && r.source == n.tunnel_ip) kept.push_back(r);
            platform_->set_routes(kept); imports_ = kept;
            std::vector<AdvertisedRoute> exports;
            for (const auto& r : exports_) for (const auto& n : next) if (r.tunnel == n.tunnel) exports.push_back(r);
            platform_->set_exports(exports); exports_ = exports;
            for (const auto& n : networks_) if (!contains(next, n)) address(n, false);
            for (const auto& n : next) if (!contains(networks_, n)) address(n, true);
            networks_ = next;
        } catch (...) { failed_ = true; close_device(); throw; }
    }
    void set_routes(const std::vector<ImportedRoute>& routes) override {
        auto next = checked_imports(config_, networks_, routes);
        if (same_imports(imports_, next)) return;
        platform_->set_routes(next); imports_ = std::move(next);
    }
    void set_exports(const std::vector<AdvertisedRoute>& routes) override {
        for (const auto& r : routes) {
            bool active = false; for (const auto& n : networks_) if (n.tunnel == r.tunnel) active = true;
            if (!active) throw std::invalid_argument("kernel export needs active network");
        }
        platform_->set_exports(routes); exports_ = routes;
    }
    void update(const KernelState& state) override {
        if (!healthy()) throw std::runtime_error("kernel interface is closed");
        if (state.networks.size() > TNLK_MAX_NETWORKS || state.peers.size() > TNLK_MAX_PEERS || state.routes.size() > TNLK_MAX_ROUTES ||
            state.ends.size() > TNLK_MAX_ENDS || state.prefixes.size() > TNLK_MAX_PREFIXES) throw std::runtime_error("kernel data-plane capacity exceeded");
        tnlk_snapshot header{}; header.abi = TNLK_ABI;
        header.networks = state.networks.size(); header.peers = state.peers.size(); header.routes = state.routes.size();
        header.ends = state.ends.size(); header.prefixes = state.prefixes.size();
        SecretBytes bytes; bytes.reserve(sizeof(header) + state.networks.size() * sizeof(tnlk_net) + state.peers.size() * sizeof(tnlk_peer) +
            state.routes.size() * sizeof(tnlk_route) + state.ends.size() * sizeof(tnlk_end) + state.prefixes.size() * sizeof(tnlk_prefix));
        append(bytes, header);
        std::map<Network, unsigned> nets; std::map<Endpoint, unsigned> peers;
        for (const auto& n : state.networks) { tnlk_net v{}; v.network = native_network(n.tunnel); v.local_ip = native_ip(n.tunnel_ip); const auto index = nets.size(); nets[n.tunnel] = index; append(bytes, v); }
        for (const auto& p : state.peers) {
            if (!p.crypto) throw std::runtime_error("kernel peer has no traffic keys");
            tnlk_peer v{}; v.endpoint = native_endpoint(p.endpoint); native_keys(v.keys, *p.crypto); v.tcp = p.tcp; v.ready = p.ready;
            for (const auto& n : p.networks) { const auto i = nets.at(n); v.networks[i / 8] |= 1U << (i % 8); }
            const auto index = peers.size(); peers[p.endpoint] = index; append(bytes, v); OPENSSL_cleanse(&v.keys, sizeof(v.keys));
        }
        for (const auto& r : state.routes) {
            if (r.hops.size() > TNLK_MAX_HOPS) throw std::runtime_error("kernel ECMP capacity exceeded");
            tnlk_route v{}; v.network = nets.at(r.network); v.destination = native_endpoint(r.destination); v.ip = native_ip(r.ip);
            v.nhops = r.hops.size(); for (unsigned i = 0; i < r.hops.size(); ++i) v.hops[i] = peers.at(r.hops[i]); append(bytes, v);
        }
        for (const auto& e : state.ends) {
            if (!e.crypto) throw std::runtime_error("kernel end-to-end session has no traffic keys");
            tnlk_end v{}; v.network = nets.at(e.network); v.destination = native_endpoint(e.destination); v.ready = e.ready;
            native_keys(v.keys, *e.crypto); append(bytes, v); OPENSSL_cleanse(&v.keys, sizeof(v.keys));
        }
        for (const auto& p : state.prefixes) {
            tnlk_prefix v{}; v.network = nets.at(p.network); v.prefix = native_network(p.prefix);
            v.publisher = native_endpoint(p.publisher); v.selected = p.selected; append(bytes, v);
        }
        if (bytes == previous_) return;
        tnlk_blob blob{}; blob.data = reinterpret_cast<std::uintptr_t>(bytes.data()); blob.length = bytes.size();
        checked(TNLK_SNAPSHOT, &blob, "publish snapshot");
        if (!previous_.empty()) OPENSSL_cleanse(previous_.data(), previous_.size());
        previous_.assign(bytes.begin(), bytes.end());
    }
    void renew() override {
        if (!healthy()) throw std::runtime_error("kernel interface is closed");
        try { checked(TNLK_RENEW, nullptr, "renew control lease"); }
        catch (...) { shutdown(); throw; }
    }
    void shutdown() override { failed_ = true; close_device(); }
    bool probe(const Endpoint& endpoint, std::uint64_t token) override {
        tnlk_probe p{}; p.peer = native_endpoint(endpoint); p.token = token;
        return healthy() && ioctl(fd_, TNLK_PROBE, &p) == 0;
    }
    bool receive_tcp(const Endpoint& endpoint, const Bytes& packet) override {
        if (!healthy() || packet.empty() || packet.size() > TNLK_MAX_PACKET) return false;
        tnlk_event event{}; event.kind = TNLK_EVENT_TCP; event.length = packet.size(); event.peer = native_endpoint(endpoint);
        Bytes buffer; append(buffer, event); buffer.insert(buffer.end(), packet.begin(), packet.end());
        return ::write(fd_, buffer.data(), buffer.size()) == static_cast<ssize_t>(buffer.size());
    }
    std::map<std::string, std::uint64_t> statistics() const override {
        tnlk_stats stats{}; std::map<std::string, std::uint64_t> result;
        if (!healthy() || ioctl(fd_, TNLK_STATS, &stats) < 0) return result;
        static const char* names[] = {"kernel_tx_packets", "kernel_rx_packets", "udp_data_sent", "udp_data_received",
            "tcp_data_sent", "tcp_data_received", "kernel_forwarded", "kernel_dropped", "kernel_no_route", "kernel_no_session",
            "kernel_auth_drop", "kernel_replay_drop", "kernel_mtu_drop", "kernel_rpf_drop", "kernel_resource_drop",
            "kernel_send_drop", "kernel_policy_drop"};
        static_assert(sizeof(names) / sizeof(names[0]) == TNLK_COUNTER_COUNT, "kernel counter ABI");
        for (unsigned i = 0; i < TNLK_COUNTER_COUNT; ++i) result[names[i]] = stats.counters[i];
        return result;
    }
private:
    void checked(unsigned long command, void* argument, const char* label) {
        if (fd_ < 0 || ioctl(fd_, command, argument) < 0)
            throw std::runtime_error(std::string("kernel backend ") + label + ": " + std::strerror(errno));
    }
    void address(const NetworkConfig& n, bool add) {
        std::vector<std::string> args{"ip", n.tunnel.address.family == 4 ? "-4" : "-6", "address", add ? "add" : "del",
            n.tunnel_ip.str() + "/" + std::to_string(n.tunnel.prefix)};
        if (add && n.tunnel.address.family == 4 && n.tunnel.prefix < 31) { args.push_back("broadcast"); args.push_back("+"); }
        args.push_back("dev"); args.push_back(name_);
        if (add && n.tunnel.address.family == 6) args.push_back("nodad");
        run_ip(args);
    }
    void read_events() {
        Bytes buffer(sizeof(tnlk_event) + TNLK_MAX_PACKET);
        for (unsigned i = 0; i < 64 && healthy(); ++i) {
            const auto count = ::read(fd_, buffer.data(), buffer.size());
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { shutdown(); return; }
            if (static_cast<std::size_t>(count) < sizeof(tnlk_event)) continue;
            tnlk_event native{}; std::memcpy(&native, buffer.data(), sizeof(native));
            if (native.length != static_cast<std::size_t>(count) - sizeof(native)) continue;
            KernelEvent event; event.kind = native.kind; event.peer = from_endpoint(native.peer);
            event.network = from_network(native.network); event.token = native.token;
            event.packet.assign(buffer.begin() + sizeof(native), buffer.begin() + count);
            if (event_) event_(std::move(event));
        }
    }
    void close_device() {
        read_.reset();
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
        platform_.reset();
        if (!previous_.empty()) OPENSSL_cleanse(previous_.data(), previous_.size());
        previous_.clear();
    }
    Configure config_;
    int fd_ = -1;
    bool failed_ = false;
    std::string name_;
    EventLoop::Handle read_;
    std::unique_ptr<SubnetPlatform> platform_;
    std::vector<NetworkConfig> networks_;
    std::vector<ImportedRoute> imports_;
    std::vector<AdvertisedRoute> exports_;
    std::function<void(KernelEvent)> event_;
    SecretBytes previous_;
};
}
std::unique_ptr<PacketDevice> open_kernel_device(EventLoop& loop, const Configure& config, const std::string& name) {
    return std::unique_ptr<PacketDevice>(new KernelDevice(loop, config, name));
}
#else
std::unique_ptr<PacketDevice> open_kernel_device(EventLoop&, const Configure&, const std::string&) {
    throw std::runtime_error("device_backend=kernel is supported only on Linux desktop/server; select tun on this platform");
}
#endif
