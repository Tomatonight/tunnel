#include "device.h"
#include "kernel_device.h"
#include "subnet_platform.h"
#include <array>
#include <cerrno>
#include <cstring>
#include <deque>
#include <set>
#include <map>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#if defined(__APPLE__)
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <netinet/in.h>
#else
#include <linux/if_tun.h>
#endif
#endif

namespace {
std::vector<NetworkConfig> assigned_networks(const std::vector<NetworkConfig>& requested) {
    std::map<Network, NetworkConfig> ordered;
    for (const auto& n : requested) {
        if (n.tunnel_ip.unspecified() && n.allocation_server.port) continue;
        if (!n.tunnel.usable_host(n.tunnel_ip)) throw std::invalid_argument("TUN address is not a usable network host");
        if (!ordered.emplace(n.tunnel, n).second) throw std::invalid_argument("duplicate TUN network");
        for (const auto& old : ordered)
            if (!(old.first == n.tunnel) && old.first.overlaps(n.tunnel)) throw std::invalid_argument("overlapping TUN networks");
    }
    std::vector<NetworkConfig> result;
    for (const auto& n : ordered) result.push_back(n.second);
    return result;
}
bool contains_address(const std::vector<NetworkConfig>& networks, const NetworkConfig& address) {
    for (const auto& n : networks) if (n.tunnel == address.tunnel && n.tunnel_ip == address.tunnel_ip) return true;
    return false;
}
bool same_addresses(const std::vector<NetworkConfig>& a, const std::vector<NetworkConfig>& b) {
    if (a.size() != b.size()) return false;
    for (const auto& n : a) if (!contains_address(b, n)) return false;
    return true;
}
void validate_name(const std::string& name, std::size_t maximum) {
    if (name.size() >= maximum) throw std::invalid_argument("TUN name too long");
    for (char c : name) if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
        !(c >= '0' && c <= '9') && c != '_' && c != '-') throw std::invalid_argument("invalid TUN name");
}
#ifndef _WIN32
#ifndef __ANDROID__
void run_program(const std::vector<std::string>& args) {
    std::vector<char*> argv; for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str())); argv.push_back(nullptr);
    const auto child = fork();
    if (child < 0) throw std::runtime_error("cannot launch interface configuration tool");
    if (!child) { execvp(argv[0], argv.data()); _exit(127); }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) throw std::runtime_error("waitpid failed");
    if (!WIFEXITED(status) || WEXITSTATUS(status)) throw std::runtime_error("interface configuration failed: " + args.front());
}
#endif
class PosixTun : public PacketDevice {
public:
    PosixTun(EventLoop& loop, const Configure& config, const std::string& requested, int& supplied, NetworkUpdate update, DeviceUpdate device_update)
        : loop_(loop), fd_(supplied), inherited_(supplied >= 0 || bool(update) || bool(device_update)),
          update_(std::move(update)), device_update_(std::move(device_update)), config_(config) {
#ifdef __ANDROID__
        (void)requested;
#endif
        supplied = -1;
        try {
            const auto initial = assigned_networks(config.networks);
            if (inherited_) {
                name_ = "inherited-tun";
                if (fd_ >= 0) { networks_ = initial; attach(); }
                else if (!initial.empty()) set_networks(initial);
                return;
            }
            else {
#if defined(__ANDROID__)
                throw std::runtime_error("Android requires an established VpnService descriptor");
#elif defined(__APPLE__)
                if (!requested.empty()) throw std::invalid_argument("macOS chooses an available utun name automatically");
                fd_ = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
                if (fd_ < 0) throw std::runtime_error("utun socket creation failed");
                ctl_info info{}; std::strcpy(info.ctl_name, "com.apple.net.utun_control");
                if (ioctl(fd_, CTLIOCGINFO, &info) < 0) throw std::runtime_error("utun control lookup failed");
                sockaddr_ctl address{}; address.sc_len = sizeof(address); address.sc_family = AF_SYSTEM;
                address.ss_sysaddr = AF_SYS_CONTROL; address.sc_id = info.ctl_id;
                if (connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) throw std::runtime_error("utun connect failed");
                char name[IFNAMSIZ]{}; socklen_t length = sizeof(name);
                if (getsockopt(fd_, SYSPROTO_CONTROL, 2 /* UTUN_OPT_IFNAME */, name, &length) < 0)
                    throw std::runtime_error("utun name lookup failed");
                name_ = name; prefix_ = true;
                run_program({"/sbin/ifconfig", name_, "mtu", std::to_string(config.tun_mtu), "up"});
#else
                validate_name(requested, IFNAMSIZ);
                fd_ = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
                if (fd_ < 0) throw std::runtime_error("cannot open /dev/net/tun");
                ifreq request{}; request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
                const auto name = requested.empty() ? std::string("tnl%d") : requested;
                std::memcpy(request.ifr_name, name.c_str(), name.size() + 1);
                if (ioctl(fd_, TUNSETIFF, &request) < 0) throw std::runtime_error("TUNSETIFF failed (requires CAP_NET_ADMIN)");
                name_ = request.ifr_name;
                run_program({"ip", "link", "set", "dev", name_, "mtu", std::to_string(config.tun_mtu), "up"});
#endif
            }
            platform_.reset(new SubnetPlatform(name_, config));
            attach(); set_networks(initial);
        } catch (...) { detach(); throw; }
    }
    ~PosixTun() override { platform_.reset(); detach(); }
    void start(Receiver receiver) override {
        if (failed_ && receiver) throw std::runtime_error("TUN device is closed after an address update failure");
        receiver_ = std::move(receiver);
        if (receiver_) { if (read_) read_->add(); }
        else { if (read_) read_->del(); if (write_) write_->del(); queue_.clear(); }
    }
    std::string name() const override { return fd_ < 0 && !failed_ ? "waiting-address" : name_; }
    bool healthy() const override { return !failed_; }
    void set_networks(const std::vector<NetworkConfig>& requested) override {
        if (failed_) throw std::runtime_error("TUN device is closed after an address update failure");
        try {
            const auto next = assigned_networks(requested);
            if (same_addresses(networks_, next)) return;
            std::vector<ImportedRoute> kept;
            for (const auto& r : routes_) for (const auto& n : next)
                if (n.tunnel == r.tunnel && n.tunnel_ip == r.source) { kept.push_back(r); break; }
            kept = checked_imports(config_, next, kept);
            if (inherited_) {
                replace_host(next, kept);
            } else {
                platform_->set_routes(kept);
                std::vector<AdvertisedRoute> exports;
                for (const auto& r : exports_) for (const auto& n : next)
                    if (n.tunnel == r.tunnel) { exports.push_back(r); break; }
                platform_->set_exports(exports); exports_ = exports;
                // Remove withdrawn addresses before installing replacements. A
                // failure closes this owned nonpersistent interface completely.
                for (const auto& old : networks_) if (!contains_address(next, old)) change_address(old, false);
                for (const auto& n : next) if (!contains_address(networks_, n)) change_address(n, true);
                queue_.clear(); if (write_) write_->del();
            }
            networks_ = next; routes_ = kept;
        } catch (...) { failed_ = true; platform_.reset(); detach(); networks_.clear(); routes_.clear(); throw; }
    }
    void set_routes(const std::vector<ImportedRoute>& requested) override {
        if (failed_) throw std::runtime_error("TUN device is closed after a configuration failure");
        try {
            const auto next = checked_imports(config_, networks_, requested);
            if (same_imports(routes_, next)) return;
            if (inherited_) {
                if (!device_update_) throw std::runtime_error("inherited TUN imported routes require a DeviceUpdate callback");
                replace_host(networks_, next);
            } else platform_->set_routes(next);
            routes_ = next;
        } catch (...) { failed_ = true; platform_.reset(); detach(); throw; }
    }
    void set_exports(const std::vector<AdvertisedRoute>& requested) override {
        if (failed_) throw std::runtime_error("TUN device is closed after a configuration failure");
        try {
            for (const auto& r : requested) {
                bool active = false; for (const auto& n : networks_) if (n.tunnel == r.tunnel) active = true;
                if (!active) throw std::invalid_argument("subnet export requires an active local tunnel");
            }
            if (inherited_) {
                if (!requested.empty()) throw std::runtime_error("host-owned TUN supports subnet access only; publishing is unsupported");
            } else platform_->set_exports(requested);
            exports_ = requested;
        } catch (...) { failed_ = true; platform_.reset(); detach(); throw; }
    }
    bool send(const Bytes& packet) override {
        if (fd_ < 0 || failed_ || packet.empty() || packet.size() > 65535 || queue_.size() >= 256) return false;
        Bytes bytes;
        if (prefix_) {
            bytes.resize(4); const auto family = htonl(packet[0] >> 4 == 6 ? AF_INET6 : AF_INET);
            std::memcpy(bytes.data(), &family, sizeof(family));
        }
        bytes.insert(bytes.end(), packet.begin(), packet.end());
        if (queue_.empty()) { const auto result = send_one(bytes); if (result != 0) return result > 0; }
        queue_.push_back(std::move(bytes)); write_->add(); return true;
    }
private:
    void replace_host(const std::vector<NetworkConfig>& networks, const std::vector<ImportedRoute>& routes) {
        if (!device_update_ && !update_) throw std::runtime_error("inherited TUN updates require a host callback");
        const int replacement = device_update_ ? device_update_(networks, routes) : update_(networks);
        if (replacement == fd_ && replacement >= 0) throw std::runtime_error("TUN host must return a new descriptor");
        if ((replacement < 0) != networks.empty()) {
            if (replacement >= 0) ::close(replacement);
            throw std::runtime_error("TUN host returned an invalid descriptor for the requested address set");
        }
        detach(); fd_ = replacement;
        if (fd_ >= 0) attach();
    }
    void attach() {
        const auto flags = fcntl(fd_, F_GETFL);
        if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(fd_, F_SETFD, FD_CLOEXEC) < 0)
            throw std::runtime_error("nonblocking TUN setup failed");
        read_ = loop_.addRead(fd_, [this](evutil_socket_t, short) { read_ready(); });
        write_ = loop_.addWrite(fd_, [this](evutil_socket_t, short) { write_ready(); });
        if (!read_ || !write_) throw std::runtime_error("TUN event allocation failed");
        if (!receiver_) read_->del();
        write_->del();
    }
    void detach() {
        read_.reset(); write_.reset(); queue_.clear();
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }
    void change_address(const NetworkConfig& n, bool add) {
#if defined(__ANDROID__)
        (void)n; (void)add;
        throw std::runtime_error("Android TUN changes require VpnService");
#elif defined(__APPLE__)
        const auto cidr = n.tunnel_ip.str() + "/" + std::to_string(n.tunnel.prefix);
        const std::string family = n.tunnel.address.family == 4 ? "inet" : "inet6";
        if (!add) {
            run_program({"/sbin/route", "-n", "delete", n.tunnel.address.family == 4 ? "-inet" : "-inet6",
                         "-net", n.tunnel.str(), "-interface", name_});
            run_program({"/sbin/ifconfig", name_, family, n.tunnel_ip.str(), "-alias"});
        } else {
            if (n.tunnel.address.family == 4) run_program({"/sbin/ifconfig", name_, family, cidr, n.tunnel_ip.str(), "alias"});
            else run_program({"/sbin/ifconfig", name_, family, cidr, "alias"});
            run_program({"/sbin/route", "-n", "add", n.tunnel.address.family == 4 ? "-inet" : "-inet6",
                         "-net", n.tunnel.str(), "-interface", name_});
        }
#else
        std::vector<std::string> args{"ip", n.tunnel.address.family == 4 ? "-4" : "-6", "address", add ? "add" : "del",
            n.tunnel_ip.str() + "/" + std::to_string(n.tunnel.prefix)};
        if (add && n.tunnel.address.family == 4 && n.tunnel.prefix < 31) { args.push_back("broadcast"); args.push_back("+"); }
        args.push_back("dev"); args.push_back(name_);
        if (add && n.tunnel.address.family == 6) args.push_back("nodad");
        run_program(args);
#endif
    }
    int send_one(const Bytes& packet) {
        const auto n = ::write(fd_, packet.data(), packet.size());
        if (n >= 0) return std::size_t(n) == packet.size() ? 1 : -1;
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
    }
    void read_ready() {
        std::array<unsigned char, 65540> buffer;
        for (unsigned i = 0; i < 64; ++i) {
            const auto n = ::read(fd_, buffer.data(), buffer.size());
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw std::runtime_error("TUN device read failed");
            const unsigned prefix = prefix_ ? 4 : 0;
            if (std::size_t(n) <= prefix) continue;
            if (prefix_) {
                std::uint32_t family; std::memcpy(&family, buffer.data(), 4); family = ntohl(family);
                if (family != AF_INET && family != AF_INET6) continue;
            }
            if (receiver_) receiver_(Bytes(buffer.begin() + prefix, buffer.begin() + n));
            if (fd_ < 0 || !receiver_) return;
        }
    }
    void write_ready() {
        for (unsigned i = 0; i < 64 && !queue_.empty(); ++i) {
            if (!send_one(queue_.front())) break;
            queue_.pop_front();
        }
        if (queue_.empty()) write_->del();
    }
    EventLoop& loop_;
    int fd_ = -1;
    bool prefix_ = false, inherited_ = false, failed_ = false;
    NetworkUpdate update_;
    DeviceUpdate device_update_;
    Configure config_;
    std::unique_ptr<SubnetPlatform> platform_;
    std::vector<NetworkConfig> networks_;
    std::vector<ImportedRoute> routes_;
    std::vector<AdvertisedRoute> exports_;
    std::string name_;
    Receiver receiver_;
    EventLoop::Handle read_, write_;
    std::deque<Bytes> queue_;
};
#else
class WindowsTun : public PacketDevice {
    using Adapter = void*; using Session = void*;
    using Create = Adapter(WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
    using Open = Adapter(WINAPI*)(LPCWSTR);
    using Close = void(WINAPI*)(Adapter);
    using Luid = void(WINAPI*)(Adapter, NET_LUID*);
    using Start = Session(WINAPI*)(Adapter, DWORD);
    using End = void(WINAPI*)(Session);
    using ReceivePacket = BYTE*(WINAPI*)(Session, DWORD*);
    using Release = void(WINAPI*)(Session, const BYTE*);
    using Allocate = BYTE*(WINAPI*)(Session, DWORD);
    using SendPacket = void(WINAPI*)(Session, const BYTE*);
public:
    WindowsTun(EventLoop& loop, const Configure& config, std::string name) : mtu_(config.tun_mtu), config_(config) {
        try {
            if (name.empty()) name = "Tunnel-" + std::to_string(GetCurrentProcessId());
            validate_name(name, 64); name_ = name;
            wchar_t executable[32768]; const auto size = GetModuleFileNameW(nullptr, executable, 32768);
            if (!size || size >= 32768) throw std::runtime_error("executable path lookup failed");
            std::wstring path(executable, size); path.resize(path.find_last_of(L"/\\") + 1); path += L"wintun.dll";
            dll_ = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!dll_) throw std::runtime_error("place the official architecture-matched wintun.dll beside tunnel.exe");
            create_ = symbol<Create>("WintunCreateAdapter"); auto open = symbol<Open>("WintunOpenAdapter");
            close_ = symbol<Close>("WintunCloseAdapter"); auto luid = symbol<Luid>("WintunGetAdapterLUID");
            auto start = symbol<Start>("WintunStartSession"); end_ = symbol<End>("WintunEndSession");
            receive_ = symbol<ReceivePacket>("WintunReceivePacket"); release_ = symbol<Release>("WintunReleaseReceivePacket");
            allocate_ = symbol<Allocate>("WintunAllocateSendPacket"); send_ = symbol<SendPacket>("WintunSendPacket");
            const std::wstring wide(name.begin(), name.end());
            auto existing = open(wide.c_str());
            if (existing) { close_(existing); throw std::runtime_error("TUN adapter name already exists"); }
            adapter_ = create_(wide.c_str(), L"Tunnel", nullptr);
            if (!adapter_) throw std::runtime_error("WintunCreateAdapter failed (administrator rights required)");
            luid(adapter_, &luid_);
            platform_.reset(new SubnetPlatform(name_, config));
            set_networks(config.networks);
            session_ = start(adapter_, 0x400000);
            if (!session_) throw std::runtime_error("WintunStartSession failed");
            timer_ = loop.addTimer(std::chrono::milliseconds(2), [this](evutil_socket_t, short) {
                if (!receiver_) return;
                for (unsigned i = 0; i < 64; ++i) {
                    DWORD size = 0; auto* data = receive_(session_, &size);
                    if (!data) { if (GetLastError() == ERROR_NO_MORE_ITEMS) return; throw std::runtime_error("Wintun read failed"); }
                    Bytes packet(data, data + size); release_(session_, data); receiver_(std::move(packet));
                    if (!session_ || failed_ || !receiver_) return;
                }
            }, true);
            if (!timer_) throw std::runtime_error("Wintun timer allocation failed");
        } catch (...) { cleanup(); throw; }
    }
    ~WindowsTun() override { cleanup(); }
    void start(Receiver receiver) override {
        if (failed_ && receiver) throw std::runtime_error("TUN device is closed after an address update failure");
        receiver_ = std::move(receiver);
    }
    std::string name() const override { return name_; }
    bool healthy() const override { return !failed_ && adapter_ != nullptr; }
    void set_networks(const std::vector<NetworkConfig>& requested) override {
        if (failed_ || !adapter_) throw std::runtime_error("TUN device is closed after an address update failure");
        try {
            const auto next = assigned_networks(requested);
            if (same_addresses(networks_, next)) return;
            std::vector<ImportedRoute> kept;
            for (const auto& r : routes_) for (const auto& n : next)
                if (n.tunnel == r.tunnel && n.tunnel_ip == r.source) { kept.push_back(r); break; }
            kept = checked_imports(config_, next, kept);
            platform_->set_routes(kept); routes_ = kept;
            std::vector<AdvertisedRoute> exports;
            for (const auto& r : exports_) for (const auto& n : next)
                if (n.tunnel == r.tunnel) { exports.push_back(r); break; }
            platform_->set_exports(exports); exports_ = exports;
            for (const auto& old : networks_) if (!contains_address(next, old)) {
                auto row = address_row(old);
                const auto result = DeleteUnicastIpAddressEntry(&row);
                if (result != NO_ERROR) throw std::runtime_error("DeleteUnicastIpAddressEntry failed: " + std::to_string(result));
            }
            for (const auto& n : next) if (!contains_address(networks_, n)) {
                configure_family(n.tunnel_ip.family == 4 ? AF_INET : AF_INET6);
                auto row = address_row(n);
                const auto result = CreateUnicastIpAddressEntry(&row);
                if (result != NO_ERROR) throw std::runtime_error("CreateUnicastIpAddressEntry failed: " + std::to_string(result));
            }
            networks_ = next;
        } catch (...) { failed_ = true; cleanup(); networks_.clear(); throw; }
    }
    void set_routes(const std::vector<ImportedRoute>& requested) override {
        if (!healthy()) throw std::runtime_error("TUN device is closed after a configuration failure");
        try {
            const auto next = checked_imports(config_, networks_, requested);
            if (same_imports(routes_, next)) return;
            platform_->set_routes(next); routes_ = next;
        } catch (...) { failed_ = true; cleanup(); throw; }
    }
    void set_exports(const std::vector<AdvertisedRoute>& requested) override {
        if (!healthy()) throw std::runtime_error("TUN device is closed after a configuration failure");
        try {
            for (const auto& r : requested) {
                bool active = false; for (const auto& n : networks_) if (n.tunnel == r.tunnel) active = true;
                if (!active) throw std::invalid_argument("subnet export requires an active local tunnel");
            }
            platform_->set_exports(requested); exports_ = requested;
        } catch (...) { failed_ = true; cleanup(); throw; }
    }
    bool send(const Bytes& packet) override {
        if (!session_ || failed_ || packet.empty() || packet.size() > 65535) return false;
        auto* data = allocate_(session_, static_cast<DWORD>(packet.size())); if (!data) return false;
        std::memcpy(data, packet.data(), packet.size()); send_(session_, data); return true;
    }
private:
    void configure_family(int family) {
        if (families_.count(family)) return;
        MIB_IPINTERFACE_ROW row; InitializeIpInterfaceEntry(&row); row.Family = ADDRESS_FAMILY(family); row.InterfaceLuid = luid_;
        if (GetIpInterfaceEntry(&row) != NO_ERROR) throw std::runtime_error("GetIpInterfaceEntry failed");
        row.NlMtu = mtu_; row.UseAutomaticMetric = FALSE; row.Metric = 0;
        if (family == AF_INET) row.SitePrefixLength = 0;
        if (SetIpInterfaceEntry(&row) != NO_ERROR) throw std::runtime_error("SetIpInterfaceEntry failed");
        families_.insert(family);
    }
    MIB_UNICASTIPADDRESS_ROW address_row(const NetworkConfig& n) const {
        MIB_UNICASTIPADDRESS_ROW row; InitializeUnicastIpAddressEntry(&row); row.InterfaceLuid = luid_;
        row.Address.si_family = n.tunnel_ip.family == 4 ? AF_INET : AF_INET6;
        if (n.tunnel_ip.family == 4) std::memcpy(&row.Address.Ipv4.sin_addr, n.tunnel_ip.bytes.data(), 4);
        else std::memcpy(&row.Address.Ipv6.sin6_addr, n.tunnel_ip.bytes.data(), 16);
        row.OnLinkPrefixLength = static_cast<UINT8>(n.tunnel.prefix); row.DadState = IpDadStatePreferred;
        return row;
    }
    template<class T> T symbol(const char* name) {
        auto* symbol = GetProcAddress(dll_, name); if (!symbol) throw std::runtime_error("unsupported Wintun API");
        T function;
        static_assert(sizeof(function) == sizeof(symbol), "Windows function pointer size mismatch");
        std::memcpy(&function, &symbol, sizeof(function)); return function;
    }
    void cleanup() {
        platform_.reset();
        timer_.reset(); if (session_) { end_(session_); session_ = nullptr; }
        if (adapter_) { close_(adapter_); adapter_ = nullptr; }
        if (dll_) { FreeLibrary(dll_); dll_ = nullptr; }
    }
    HMODULE dll_ = nullptr; Adapter adapter_ = nullptr; Session session_ = nullptr;
    Create create_ = nullptr; Close close_ = nullptr; End end_ = nullptr;
    ReceivePacket receive_ = nullptr; Release release_ = nullptr; Allocate allocate_ = nullptr; SendPacket send_ = nullptr;
    Receiver receiver_; std::string name_; EventLoop::Handle timer_;
    NET_LUID luid_{};
    unsigned mtu_;
    bool failed_ = false;
    std::set<int> families_;
    std::vector<NetworkConfig> networks_;
    Configure config_;
    std::unique_ptr<SubnetPlatform> platform_;
    std::vector<ImportedRoute> routes_;
    std::vector<AdvertisedRoute> exports_;
};
#endif
}
std::unique_ptr<PacketDevice> open_tun(EventLoop& loop, const Configure& config, const std::string& name, int supplied_fd, NetworkUpdate update, DeviceUpdate device_update) {
    if (config.device_backend != "tun") {
#ifndef _WIN32
        if (supplied_fd >= 0) ::close(supplied_fd);
#endif
        throw std::invalid_argument("TUN host does not support device_backend=kernel; select tun or use the Linux native launcher");
    }
#ifdef _WIN32
    if (supplied_fd >= 0 || update || device_update) throw std::invalid_argument("Windows does not accept POSIX TUN descriptors or host descriptor callbacks");
    return std::unique_ptr<PacketDevice>(new WindowsTun(loop, config, name));
#else
    try { return std::unique_ptr<PacketDevice>(new PosixTun(loop, config, name, supplied_fd, std::move(update), std::move(device_update))); }
    catch (...) { if (supplied_fd >= 0) ::close(supplied_fd); throw; }
#endif
}
std::unique_ptr<PacketDevice> open_device(EventLoop& loop, const Configure& config, const std::string& name, int supplied_fd, NetworkUpdate update, DeviceUpdate device_update) {
    if (config.device_backend == "tun") return open_tun(loop, config, name, supplied_fd, std::move(update), std::move(device_update));
    if (supplied_fd >= 0) {
#ifndef _WIN32
        ::close(supplied_fd);
#endif
        throw std::invalid_argument("kernel device backend does not accept an inherited TUN descriptor");
    }
    if (update || device_update) throw std::invalid_argument("kernel device backend does not accept TUN host callbacks");
    if (config.device_backend != "kernel") throw std::invalid_argument("unknown device backend");
    return open_kernel_device(loop, config, name);
}
