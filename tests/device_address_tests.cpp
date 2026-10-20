#include "device.h"
#include "subnet_platform.h"
#include "udp_transport.h"
#include "third_party/nlohmann/json.hpp"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#else
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
unsigned checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)
NetworkConfig address(const char* subnet, const char* ip) {
    NetworkConfig result; result.tunnel = Network::parse(subnet); result.tunnel_ip = IpAddress::parse(ip); return result;
}
const NetworkConfig a = address("10.253.211.0/24", "10.253.211.17");
const NetworkConfig b = address("10.253.212.0/24", "10.253.212.18");
const NetworkConfig v6 = address("fd92:ace1:7211::/64", "fd92:ace1:7211::17");
template<class F> void rejects(F f) {
    bool rejected = false; try { f(); } catch (const std::exception&) { rejected = true; } CHECK(rejected);
}
void egress_probe_tests() {
    auto probes = subnet_probe_addresses(Network::parse("fd00:91::/64"), {IpAddress::parse("fd00:91::1"), IpAddress::parse("fd00:91::2")});
    CHECK(!probes.empty() && probes.front() == IpAddress::parse("fd00:91::3"));
    for (const auto& ip : probes) CHECK(ip != IpAddress::parse("fd00:91::"));
    probes = subnet_probe_addresses(Network::parse("192.0.2.0/24"), {IpAddress::parse("192.0.2.1")});
    CHECK(!probes.empty() && probes.front() == IpAddress::parse("192.0.2.2"));
    probes = subnet_probe_addresses(Network::parse("192.0.2.0/31"), {IpAddress::parse("192.0.2.1")});
    CHECK(probes.size() == 1 && probes.front() == IpAddress::parse("192.0.2.0"));
    probes = subnet_probe_addresses(Network::parse("fd00:91::/127"), {IpAddress::parse("fd00:91::1")});
    CHECK(probes.size() == 1 && probes.front() == IpAddress::parse("fd00:91::"));
    for (const auto* cidr : {"192.0.2.9/32", "fd00:91::9/128"}) {
        const auto prefix = Network::parse(cidr);
        probes = subnet_probe_addresses(prefix, {});
        CHECK(probes.size() == 1 && probes.front() == prefix.address);
        CHECK(subnet_probe_addresses(prefix, {prefix.address}).empty());
    }
    probes = subnet_probe_addresses(Network::parse("192.0.2.0/30"), {IpAddress::parse("192.0.2.1"), IpAddress::parse("192.0.2.2")});
    CHECK(probes.empty());
}
class LegacyDevice : public PacketDevice {
    void start(Receiver) override {}
    bool send(const Bytes&) override { return false; }
    std::string name() const override { return "legacy-test"; }
};
#ifndef _WIN32
struct Pair {
    int device = -1, host = -1;
    Pair() { int pair[2]; if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) throw std::runtime_error("socketpair failed"); device = pair[0]; host = pair[1]; }
    int take() { int fd = device; device = -1; return fd; }
    ~Pair() { if (device >= 0) close(device); if (host >= 0) close(host); }
};
void spin(EventLoop& loop) {
    auto deadline = loop.addTimer(std::chrono::milliseconds(15), [&](evutil_socket_t, short) { loop.breakLoop(); }); loop.run();
}
bool closed(int fd) { errno = 0; return fcntl(fd, F_GETFD) == -1 && errno == EBADF; }
void descriptor_tests() {
    EventLoop loop; Configure config;
    config.device_backend = "tun";
    auto pending = a; pending.tunnel_ip = IpAddress(); pending.allocation_server = Endpoint::parse("127.0.0.1:49001");
    config.networks = {pending};
    Pair first, second, third; unsigned calls = 0; bool fail = false;
    const int first_fd = first.device, second_fd = second.device, third_fd = third.device;
    auto device = open_tun(loop, config, "", -1, [&](const std::vector<NetworkConfig>& networks) {
        ++calls;
        if (fail) throw std::runtime_error("injected host update failure");
        if (networks.empty()) return -1;
        if (calls == 1) { CHECK(networks.size() == 1); return first.take(); }
        if (calls == 2) { CHECK(networks.size() == 2); return second.take(); }
        return third.take();
    });
    CHECK(calls == 0 && device->healthy() && device->name() == "waiting-address");
    CHECK(!device->send(Bytes{1}));
    unsigned received = 0;
    device->start([&](Bytes packet) { CHECK(packet == Bytes({0x45, 1, 2})); ++received; });
    device->set_networks({pending}); CHECK(calls == 0);
    device->set_networks({a}); CHECK(calls == 1 && device->healthy());
    CHECK(write(first.host, "\x45\x01\x02", 3) == 3); spin(loop); CHECK(received == 1);
    CHECK(device->send(Bytes({3, 4}))); unsigned char output[8]; CHECK(recv(first.host, output, sizeof(output), MSG_DONTWAIT) == 2);
    device->set_networks({b, a}); CHECK(calls == 2 && closed(first_fd));
    device->set_networks({a, b}); CHECK(calls == 2); // Order alone must not rebuild a VPN.
    CHECK(write(second.host, "\x45\x01\x02", 3) == 3); spin(loop); CHECK(received == 2);
    device->set_networks({}); CHECK(calls == 3 && closed(second_fd) && device->healthy());
    CHECK(!device->send(Bytes{1}));
    device->set_networks({a}); CHECK(calls == 4 && device->healthy());
    fail = true; rejects([&] { device->set_networks({b}); });
    CHECK(!device->healthy() && closed(third_fd) && !device->send(Bytes{1}));
    rejects([&] { device->set_networks({a}); });

    Pair inherited; const int inherited_fd = inherited.device; config.networks = {a};
    auto legacy = open_tun(loop, config, "", inherited.take());
    legacy->set_networks({a}); CHECK(legacy->healthy());
    rejects([&] { legacy->set_networks({b}); }); CHECK(!legacy->healthy() && closed(inherited_fd));

    Pair invalid; const int invalid_fd = invalid.device; config.networks.clear();
    auto wrong = open_tun(loop, config, "", -1, [&](const std::vector<NetworkConfig>&) { return -1; });
    rejects([&] { wrong->set_networks({a}); }); CHECK(!wrong->healthy());
    auto same = open_tun(loop, config, "", invalid.take(), [&](const std::vector<NetworkConfig>&) { return invalid_fd; });
    rejects([&] { same->set_networks({a}); }); CHECK(!same->healthy() && closed(invalid_fd));

    Pair reentrant; const int reentrant_fd = reentrant.device; config.networks = {a};
    auto during_read = open_tun(loop, config, "", reentrant.take(), [&](const std::vector<NetworkConfig>&) { return -1; });
    during_read->start([&](Bytes) { during_read->set_networks({}); });
    CHECK(write(reentrant.host, "\x45\x01\x02", 3) == 3); spin(loop);
    CHECK(during_read->healthy() && closed(reentrant_fd)); // Callback removal must not read a closed fd.
}
void imported_descriptor_tests() {
    EventLoop loop; Configure config; config.networks = {a, b};
    config.device_backend = "tun";
    ImportedRoute route; route.tunnel = a.tunnel; route.source = a.tunnel_ip; route.prefix = Network::parse("192.0.2.0/24");
    unsigned calls = 0; std::vector<std::unique_ptr<Pair>> pairs;
    std::vector<ImportedRoute> last_routes; std::vector<NetworkConfig> last_networks;
    auto device = open_tun(loop, config, "", -1, {}, [&](const std::vector<NetworkConfig>& networks, const std::vector<ImportedRoute>& routes) {
        ++calls; last_networks = networks; last_routes = routes;
        if (networks.empty()) return -1;
        pairs.emplace_back(new Pair); return pairs.back()->take();
    });
    CHECK(calls == 1 && last_networks.size() == 2 && last_routes.empty());
    device->set_routes({route}); CHECK(calls == 2 && last_routes.size() == 1 && last_networks.size() == 2);
    device->set_routes({route}); CHECK(calls == 2);
    CHECK(device->send(Bytes({3, 4}))); unsigned char output[8];
    CHECK(recv(pairs.back()->host, output, sizeof(output), MSG_DONTWAIT) == 2);
    device->set_networks({b}); CHECK(calls == 3 && last_routes.empty() && last_networks.size() == 1);
    device->set_routes({}); CHECK(calls == 3);
    device->set_networks({}); CHECK(calls == 4 && last_networks.empty() && device->healthy());
    device->set_exports({}); CHECK(device->healthy());
    rejects([&] { device->set_routes({route}); }); CHECK(!device->healthy());

    CHECK(checked_imports(config, config.networks, {route}).size() == 1);
    auto wrong = route; wrong.source = b.tunnel_ip;
    rejects([&] { checked_imports(config, config.networks, {wrong}); });
    wrong = route; wrong.prefix = a.tunnel;
    rejects([&] { checked_imports(config, config.networks, {wrong}); });
    wrong = route; wrong.prefix = Network::parse("0.0.0.0/0");
    rejects([&] { checked_imports(config, config.networks, {wrong}); });
    wrong = route; wrong.prefix = Network::parse("192.0.2.0/25");
    rejects([&] { checked_imports(config, config.networks, {route, wrong}); });
    PeerConfig peer; peer.address = Endpoint::parse("192.0.2.9:65535"); config.peers.push_back(peer);
    rejects([&] { checked_imports(config, config.networks, {route}); });
}
#endif

#ifdef _WIN32
NET_LUID interface_id(const std::string& name) {
    NET_LUID luid{}; const std::wstring wide(name.begin(), name.end());
    CHECK(ConvertInterfaceAliasToLuid(wide.c_str(), &luid) == NO_ERROR); return luid;
}
bool present(const std::string& name, const NetworkConfig& n) {
    const auto luid = interface_id(name); PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    CHECK(GetUnicastIpAddressTable(AF_UNSPEC, &table) == NO_ERROR); bool found = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i]; if (row.InterfaceLuid.Value != luid.Value) continue;
        if (n.tunnel_ip.family == 4 && row.Address.si_family == AF_INET)
            found |= !std::memcmp(&row.Address.Ipv4.sin_addr, n.tunnel_ip.bytes.data(), 4) && row.OnLinkPrefixLength == n.tunnel.prefix;
        if (n.tunnel_ip.family == 6 && row.Address.si_family == AF_INET6)
            found |= !std::memcmp(&row.Address.Ipv6.sin6_addr, n.tunnel_ip.bytes.data(), 16) && row.OnLinkPrefixLength == n.tunnel.prefix;
    }
    FreeMibTable(table); return found;
}
void remove_externally(const std::string& name, const NetworkConfig& n) {
    MIB_UNICASTIPADDRESS_ROW row; InitializeUnicastIpAddressEntry(&row); row.InterfaceLuid = interface_id(name);
    row.Address.si_family = AF_INET; std::memcpy(&row.Address.Ipv4.sin_addr, n.tunnel_ip.bytes.data(), 4);
    CHECK(DeleteUnicastIpAddressEntry(&row) == NO_ERROR);
}
#else
bool present(const std::string& name, const NetworkConfig& n) {
    ifaddrs* addresses = nullptr; CHECK(getifaddrs(&addresses) == 0); bool found = false;
    for (auto* entry = addresses; entry; entry = entry->ifa_next) {
        if (name != entry->ifa_name || !entry->ifa_addr) continue;
        if (n.tunnel_ip.family == 4 && entry->ifa_addr->sa_family == AF_INET)
            found |= !std::memcmp(&reinterpret_cast<sockaddr_in*>(entry->ifa_addr)->sin_addr, n.tunnel_ip.bytes.data(), 4);
        if (n.tunnel_ip.family == 6 && entry->ifa_addr->sa_family == AF_INET6)
            found |= !std::memcmp(&reinterpret_cast<sockaddr_in6*>(entry->ifa_addr)->sin6_addr, n.tunnel_ip.bytes.data(), 16);
    }
    freeifaddrs(addresses); return found;
}
void remove_externally(const std::string& name, const NetworkConfig& n) {
    const auto cidr = n.tunnel_ip.str() + "/" + std::to_string(n.tunnel.prefix);
    const auto child = fork(); CHECK(child >= 0);
    if (!child) {
#ifdef __APPLE__
        execl("/sbin/ifconfig", "ifconfig", name.c_str(), "inet", n.tunnel_ip.str().c_str(), "-alias", nullptr);
#else
        execlp("ip", "ip", "-4", "address", "del", cidr.c_str(), "dev", name.c_str(), nullptr);
#endif
        _exit(127);
    }
    int status; CHECK(waitpid(child, &status, 0) == child); CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
#endif
#if defined(_WIN32) || !defined(__APPLE__)
struct SystemRoute { Network prefix; std::uint64_t interface_id; };
std::vector<SystemRoute> system_routes() {
    std::vector<SystemRoute> result;
#ifdef _WIN32
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    CHECK(GetIpForwardTable2(AF_UNSPEC, &table) == NO_ERROR);
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i]; const auto& prefix = row.DestinationPrefix;
        if (!prefix.PrefixLength) continue;
        SystemRoute route;
        route.prefix = Network::parse(Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&prefix.Prefix)).ip.str() + "/" + std::to_string(prefix.PrefixLength));
        route.interface_id = row.InterfaceLuid.Value; result.push_back(route);
    }
    FreeMibTable(table);
#else
    for (const auto* family : {"-4", "-6"}) {
        FILE* output = std::tmpfile(); CHECK(output != nullptr);
        const auto child = fork(); CHECK(child >= 0);
        if (!child) {
            if (dup2(fileno(output), STDOUT_FILENO) < 0) _exit(126);
            execlp("ip", "ip", "-j", family, "route", "show", "table", "all", nullptr); _exit(127);
        }
        int status = 0; CHECK(waitpid(child, &status, 0) == child);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) { std::fclose(output); throw std::runtime_error("cannot inspect routes for live test"); }
        std::rewind(output); std::string text; char buffer[4096]; std::size_t length;
        while ((length = std::fread(buffer, 1, sizeof(buffer), output))) text.append(buffer, length);
        std::fclose(output);
        for (const auto& item : nlohmann::json::parse(text)) {
            if (!item.count("dst")) continue;
            auto destination = item.at("dst").get<std::string>(); if (destination == "default") continue;
            if (destination.find('/') == std::string::npos) destination += std::string(family) == "-4" ? "/32" : "/128";
            SystemRoute route; route.prefix = Network::parse(destination);
            route.interface_id = if_nametoindex(item.value("dev", std::string()).c_str());
            if (route.prefix.prefix) result.push_back(route);
        }
    }
#endif
    return result;
}
ImportedRoute unused_route(const NetworkConfig& source) {
    const auto existing = system_routes();
    const std::vector<std::string> candidates = source.tunnel_ip.family == 4
        ? std::vector<std::string>{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
        : std::vector<std::string>{"2001:db8:ff11::/64", "2001:db8:ff12::/64", "2001:db8:ff13::/64"};
    for (const auto& candidate : candidates) {
        const auto prefix = Network::parse(candidate); bool conflict = false;
        for (const auto& old : existing) if (old.prefix.overlaps(prefix)) conflict = true;
        if (!conflict) { ImportedRoute result; result.tunnel = source.tunnel; result.prefix = prefix; result.source = source.tunnel_ip; return result; }
    }
    throw std::runtime_error("no unused documentation subnet is available for the live route test");
}
void live_route_test(PacketDevice& device, const std::string& name, const NetworkConfig& source) {
    const auto imported = unused_route(source);
#ifdef _WIN32
    const auto id = interface_id(name).Value;
#else
    const auto id = if_nametoindex(name.c_str());
#endif
    device.set_routes({imported}); bool present = false;
    for (const auto& route : system_routes()) if (route.prefix == imported.prefix) {
        CHECK(route.interface_id == id); present = true;
    }
    CHECK(present && device.healthy());
    device.set_routes({});
    for (const auto& route : system_routes()) CHECK(!(route.prefix == imported.prefix));
    CHECK(device.healthy());
}
#endif
void live_test() {
    EventLoop loop; Configure config;
    config.device_backend = "tun";
    auto pending = a; pending.tunnel_ip = IpAddress(); pending.allocation_server = Endpoint::parse("127.0.0.1:49001");
    config.networks = {pending};
    auto device = open_tun(loop, config); const auto name = device->name();
#ifdef _WIN32
    const auto original_id = interface_id(name).Value;
#else
    const auto original_id = if_nametoindex(name.c_str()); CHECK(original_id != 0);
#endif
    CHECK(device->healthy() && !present(name, a));
    device->set_networks({a}); CHECK(present(name, a) && !present(name, b));
#if defined(_WIN32) || !defined(__APPLE__)
    live_route_test(*device, name, a);
#endif
    device->set_networks({a, b, v6}); CHECK(device->healthy() && device->name() == name);
    CHECK(present(name, a) && present(name, b) && present(name, v6));
#if defined(_WIN32) || !defined(__APPLE__)
    live_route_test(*device, name, v6);
#endif
    device->set_networks({v6, b, a}); CHECK(present(name, a) && present(name, b));
    device->set_networks({b, v6}); CHECK(!present(name, a) && present(name, b) && present(name, v6));
#ifdef _WIN32
    CHECK(interface_id(name).Value == original_id);
#else
    CHECK(if_nametoindex(name.c_str()) == original_id);
#endif
    device->set_networks({}); CHECK(device->healthy() && !present(name, b) && !present(name, v6));
    device->set_networks({a}); CHECK(present(name, a));
    remove_externally(name, a); // Only the interface created and owned by this test.
    rejects([&] { device->set_networks({}); }); CHECK(!device->healthy() && !device->send(Bytes{0x45}));
}
}
int main(int argc, char** argv) {
    try {
        SocketSystem sockets;
        egress_probe_tests();
        LegacyDevice old; CHECK(old.healthy()); rejects([&] { old.set_networks({a}); });
#ifndef _WIN32
        descriptor_tests(); imported_descriptor_tests();
#else
        Configure multi; multi.networks = {a, b, v6};
        ImportedRoute imported; imported.tunnel = a.tunnel; imported.source = a.tunnel_ip; imported.prefix = Network::parse("192.0.2.0/24");
        rejects([&] { checked_imports(multi, multi.networks, {imported}); });
#endif
        if (argc == 2 && std::string(argv[1]) == "--live") live_test();
        else if (argc != 1) throw std::invalid_argument("usage: device_address_tests [--live]");
        std::cout << "device address checks passed: " << checks << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
