#include "node.h"
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <csignal>
#endif
namespace {
using Json = wire::Json;
unsigned checks = 0;
std::function<void()> diagnostics;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)
class MemoryDevice : public PacketDevice {
public:
    Receiver receiver;
    std::vector<Bytes> delivered;
    std::vector<NetworkConfig> networks;
    std::vector<ImportedRoute> imported;
    std::vector<AdvertisedRoute> exported;
    unsigned updates = 0;
    void start(Receiver r) override { receiver = std::move(r); }
    bool send(const Bytes& b) override { delivered.push_back(b); return true; }
    std::string name() const override { return "managed-memory-device"; }
    void set_networks(const std::vector<NetworkConfig>& n) override { networks = n; ++updates; }
    void set_routes(const std::vector<ImportedRoute>& r) override { imported = r; }
    void set_exports(const std::vector<AdvertisedRoute>& r) override { exported = r; }
    void inject(const Bytes& b) { if (receiver) receiver(b); }
};
void until(EventLoop& loop, std::function<bool()> predicate, unsigned timeout = 12000) {
    auto poll = loop.addTimer(std::chrono::milliseconds(10), [&](evutil_socket_t, short) { if (predicate()) loop.breakLoop(); }, true);
    auto deadline = loop.addTimer(std::chrono::milliseconds(timeout), [&](evutil_socket_t, short) { loop.breakLoop(); });
    loop.run(); if (!predicate() && diagnostics) diagnostics(); CHECK(predicate());
}
void spin(EventLoop& loop, unsigned milliseconds) {
    auto done = loop.addTimer(std::chrono::milliseconds(milliseconds), [&](evutil_socket_t, short) { loop.breakLoop(); }); loop.run();
}
std::vector<Endpoint> ports(EventLoop& loop, unsigned count) {
    (void)loop;
    struct Reservations {
        std::vector<evutil_socket_t> sockets;
        ~Reservations() { for (auto fd : sockets) evutil_closesocket(fd); }
    } held;
    // Node.start() may dial peers before their listeners exist. A test listener
    // must not be a port the OS can select for one of those outgoing sockets.
    static unsigned cursor = static_cast<unsigned>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() % 10000);
    std::vector<Endpoint> result;
    for (unsigned tried = 0; tried < 10000 && result.size() < count; ++tried) {
        Endpoint e; e.ip = IpAddress::parse("127.0.0.1"); e.port = static_cast<std::uint16_t>(20000 + cursor++ % 10000);
        const auto tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (tcp == EVUTIL_INVALID_SOCKET || udp == EVUTIL_INVALID_SOCKET) {
            if (tcp != EVUTIL_INVALID_SOCKET) evutil_closesocket(tcp);
            if (udp != EVUTIL_INVALID_SOCKET) evutil_closesocket(udp);
            throw std::runtime_error("cannot reserve test sockets");
        }
#ifdef _WIN32
        const int exclusive = 1;
        if (setsockopt(tcp, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) ||
            setsockopt(udp, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive))) {
            evutil_closesocket(tcp); evutil_closesocket(udp); throw std::runtime_error("cannot reserve exclusive test sockets");
        }
#endif
        int length; const auto address = e.sockaddr_value(&length);
        if (::bind(tcp, reinterpret_cast<const sockaddr*>(&address), length) ||
            ::bind(udp, reinterpret_cast<const sockaddr*>(&address), length) || listen(tcp, 1)) {
            evutil_closesocket(tcp); evutil_closesocket(udp); continue;
        }
        held.sockets.push_back(tcp); held.sockets.push_back(udp); result.push_back(e);
    }
    CHECK(result.size() == count);
    return result;
}
NodeOptions options() {
    // Renewal persists both leases synchronously. Keep this lifecycle test
    // below a disk-stress workload, including on Windows WRITE_THROUGH files.
    NodeOptions o; o.tick_ms = 10; o.heartbeat_ms = 1000; o.failure_timeout_ms = 10000;
    o.handshake_timeout_ms = 10000; o.reconnect_ms = 100; o.address_proof_lifetime_ms = 12000;
    o.log = [](const std::string& s) { std::cerr << s << '\n'; }; return o;
}
Json client(const Endpoint& local, const Endpoint& remote, const Endpoint& server, bool first) {
    return {{"address", local.str()}, {"listen", {{"bind_address", local.str()}}},
        {"networks", Json::array({first ? "10.99.0.1/24" : "10.99.0.2/24"})},
        {"address_clients", Json::array({{{"address", server.str()}, {"shared_key", first ? "test-client-a" : "test-client-b"},
            {"networks", Json::array({"10.77.0.0/24", "fd00:77::/64"})}}})},
        {"peers", Json::array({{{"address", remote.str()}, {"shared_key", "test-pairwise-peer"},
            {"networks", Json::array({"10.99.0.0/24", "10.77.0.0/24", "fd00:77::/64"})}}})}};
}
Json server(const Endpoint& address, const Endpoint& a, const Endpoint& b, const std::string& state) {
    const auto pools = Json::array({"10.77.0.0/24", "fd00:77::/64"});
    return {{"address_server", {{"address", address.str()}, {"bind_address", address.str()}, {"state_file", state},
        {"reclaim_after", 120}, {"networks", pools}, {"clients", Json::array({
            {{"address", a.str()}, {"shared_key", "test-client-a"}, {"networks", pools}},
            {{"address", b.str()}, {"shared_key", "test-client-b"}, {"networks", pools}}
        })}}}};
}
std::string ip(Node& node, const std::string& network) {
    const auto status = node.status();
    for (const auto& n : status.at("networks")) if (n.at("network") == network && n.at("active") == true) return n.at("ip");
    return {};
}
bool route(Node& node, const Endpoint& target, const std::string& network) {
    const auto status = node.status();
    for (const auto& r : status.at("routes")) if (r.at("node") == target.str() && r.at("network") == network) return true;
    return false;
}
bool imported(const MemoryDevice& device, const std::string& network, const std::string& prefix) {
    for (const auto& r : device.imported) if (r.tunnel.str() == network && r.prefix.str() == prefix) return true;
    return false;
}
bool exported(const MemoryDevice& device, const std::string& network, const std::string& prefix) {
    for (const auto& r : device.exported) if (r.tunnel.str() == network && r.prefix.str() == prefix) return true;
    return false;
}
std::string session(Node& node, const std::string& network) {
    const auto status = node.status();
    for (const auto& s : status.at("end_sessions")) if (s.at("network") == network && s.at("ready") == true) return s.at("id");
    return {};
}
std::uint64_t counter(Node& node, const std::string& name) { return node.status().at("counters").value(name, std::uint64_t(0)); }
Bytes packet(const std::string& source, const std::string& destination) {
    const auto src = IpAddress::parse(source), dst = IpAddress::parse(destination);
    CHECK(src.family == dst.family);
    Bytes bytes(100, 0);
    if (src.family == 4) {
        bytes[0] = 0x45; bytes[3] = 100; bytes[8] = 64; bytes[9] = 17;
        std::copy(src.bytes.begin(), src.bytes.begin() + 4, bytes.begin() + 12);
        std::copy(dst.bytes.begin(), dst.bytes.begin() + 4, bytes.begin() + 16);
        bytes[20] = 0x12; bytes[21] = 0x34; bytes[22] = 0x56; bytes[23] = 0x78; bytes[25] = 80;
    } else {
        bytes[0] = 0x60; bytes[5] = 60; bytes[6] = 17; bytes[7] = 64;
        std::copy(src.bytes.begin(), src.bytes.end(), bytes.begin() + 8);
        std::copy(dst.bytes.begin(), dst.bytes.end(), bytes.begin() + 24);
        bytes[40] = 0x12; bytes[41] = 0x34; bytes[42] = 0x56; bytes[43] = 0x78; bytes[45] = 60;
    }
    bytes.back() = 0xaa; return bytes;
}
void transfer(EventLoop& loop, MemoryDevice& source, MemoryDevice& target, const Bytes& bytes) {
    const auto count = target.delivered.size(); source.inject(bytes);
    until(loop, [&] { return target.delivered.size() > count; }); CHECK(target.delivered.back() == bytes);
}
void run(const std::string& state) {
    EventLoop loop; const auto endpoints = ports(loop, 4);
    auto ca = client(endpoints[0], endpoints[1], endpoints[2], true);
    auto cb = client(endpoints[1], endpoints[0], endpoints[2], false);
    ca["advertise_routes"] = Json::array({
        {{"tunnel", "10.99.0.0/24"}, {"prefix", "10.100.0.0/24"}},
        {{"tunnel", "10.77.0.0/24"}, {"prefix", "10.78.0.0/24"}, {"snat", true}}
    });
    // Use one TCP dial direction: membership tests must begin on a stable
    // physical link. Simultaneous-dial arbitration is covered by runtime_tests.
    cb["listen"]["enabled"] = false;
    auto cs = server(endpoints[2], endpoints[0], endpoints[1], state);
    auto* da = new MemoryDevice; auto* db = new MemoryDevice;
    Node a(loop, parse_config(ca.dump()), std::unique_ptr<PacketDevice>(da), options());
    std::unique_ptr<Node> b(new Node(loop, parse_config(cb.dump()), std::unique_ptr<PacketDevice>(db), options()));
    diagnostics = [&] { std::cerr << a.status().dump(2) << '\n' << b->status().dump(2) << '\n'; };
    a.start(); b->start();
    std::cerr << "managed: static network while allocator is offline\n";
    until(loop, [&] { return route(a, endpoints[1], "10.99.0.0/24") && route(*b, endpoints[0], "10.99.0.0/24") &&
        a.status().at("pending_connections") == 0 && b->status().at("pending_connections") == 0 &&
        imported(*db, "10.99.0.0/24", "10.100.0.0/24"); });
    spin(loop, 200);
    CHECK(ip(a, "10.77.0.0/24").empty()); CHECK(da->updates == 0);
    CHECK(exported(*da, "10.99.0.0/24", "10.100.0.0/24")); CHECK(da->exported.size() == 1);
    CHECK(db->imported.size() == 1 && db->imported[0].source == IpAddress::parse("10.99.0.2"));
    CHECK(da->imported.empty() && db->exported.empty());
    const auto static_packet = packet("10.99.0.1", "10.99.0.2"); transfer(loop, *da, *db, static_packet);
    const auto old_session = session(a, "10.99.0.0/24"); CHECK(!old_session.empty());
    const auto old_peer_up = counter(a, "peer_up");
    const auto old_peer_down = counter(a, "peer_down");
    std::unique_ptr<Node> s(new Node(loop, parse_config(cs.dump()), {}, options())); s->start();
    std::cerr << "managed: activate IPv4 and IPv6 pools on existing peer\n";
    until(loop, [&] { return route(a, endpoints[1], "10.77.0.0/24") && route(a, endpoints[1], "fd00:77::/64") &&
        imported(*db, "10.77.0.0/24", "10.78.0.0/24"); });
    CHECK(s->status().at("device") == ""); CHECK(s->status().at("peers").empty());
    CHECK(counter(a, "peer_up") == old_peer_up);
    CHECK(session(a, "10.99.0.0/24") == old_session);
    const auto av4 = ip(a, "10.77.0.0/24"), bv4 = ip(*b, "10.77.0.0/24");
    const auto av6 = ip(a, "fd00:77::/64"), bv6 = ip(*b, "fd00:77::/64");
    CHECK(!av4.empty() && av4 != bv4); CHECK(!av6.empty() && av6 != bv6);
    CHECK(da->exported.size() == 2 && db->imported.size() == 2);
    CHECK(exported(*da, "10.77.0.0/24", "10.78.0.0/24"));
    CHECK(imported(*db, "10.99.0.0/24", "10.100.0.0/24"));
    for (const auto& r : db->imported) if (r.tunnel.str() == "10.77.0.0/24") CHECK(r.source.str() == bv4);
    transfer(loop, *da, *db, packet(av4, bv4)); transfer(loop, *db, *da, packet(bv6, av6));
    const auto updates = da->updates;
    const auto expiration = a.status().at("address_service").at("clients")[0].at("grants")[0].at("expires_at");
    until(loop, [&] { return a.status().at("address_service").at("clients")[0].at("grants")[0].at("expires_at") != expiration; });
    CHECK(da->updates == updates);
    std::cerr << "managed: withdraw only managed networks on server loss\n";
    s->stop(); s.reset();
    until(loop, [&] { return ip(a, "10.77.0.0/24").empty() && ip(*b, "fd00:77::/64").empty() &&
        !route(a, endpoints[1], "10.77.0.0/24") && !route(*b, endpoints[0], "fd00:77::/64") &&
        !imported(*db, "10.77.0.0/24", "10.78.0.0/24") && !exported(*da, "10.77.0.0/24", "10.78.0.0/24"); });
    CHECK(da->networks.size() == 1); CHECK(db->networks.size() == 1);
    CHECK(da->exported.size() == 1 && db->imported.size() == 1);
    CHECK(exported(*da, "10.99.0.0/24", "10.100.0.0/24"));
    CHECK(imported(*db, "10.99.0.0/24", "10.100.0.0/24"));
    CHECK(counter(a, "peer_up") == old_peer_up); CHECK(counter(a, "peer_down") == old_peer_down);
    CHECK(session(a, "10.99.0.0/24") == old_session);
    CHECK(session(a, "10.77.0.0/24").empty());
    transfer(loop, *da, *db, static_packet);
    const auto delivered = db->delivered.size(); da->inject(packet(av4, bv4)); spin(loop, 100); CHECK(db->delivered.size() == delivered);
    std::cerr << "managed: restart allocator, retain IP and unrelated sessions\n";
    s.reset(new Node(loop, parse_config(cs.dump()), {}, options())); s->start();
    until(loop, [&] { return route(a, endpoints[1], "10.77.0.0/24") && route(*b, endpoints[0], "fd00:77::/64") &&
        imported(*db, "10.77.0.0/24", "10.78.0.0/24"); });
    CHECK(ip(a, "10.77.0.0/24") == av4); CHECK(ip(*b, "10.77.0.0/24") == bv4);
    CHECK(ip(a, "fd00:77::/64") == av6); CHECK(session(a, "10.99.0.0/24") == old_session);
    CHECK(da->exported.size() == 2 && db->imported.size() == 2);
    CHECK(exported(*da, "10.77.0.0/24", "10.78.0.0/24"));
    CHECK(imported(*db, "10.99.0.0/24", "10.100.0.0/24"));
    transfer(loop, *da, *db, packet(av4, bv4));
    std::cerr << "managed: different allocator cannot join the same managed tunnel\n";
    b->stop(); b.reset();
    auto cs2 = server(endpoints[3], endpoints[0], endpoints[1], state + ".second");
    Node other(loop, parse_config(cs2.dump()), {}, options()); other.start();
    cb["address_clients"][0]["address"] = endpoints[3].str();
    db = new MemoryDevice; b.reset(new Node(loop, parse_config(cb.dump()), std::unique_ptr<PacketDevice>(db), options())); b->start();
    until(loop, [&] { return !ip(*b, "10.77.0.0/24").empty() && route(a, endpoints[1], "10.99.0.0/24"); });
    spin(loop, 300); CHECK(!route(a, endpoints[1], "10.77.0.0/24"));
    CHECK(!imported(*db, "10.77.0.0/24", "10.78.0.0/24"));
    CHECK(imported(*db, "10.99.0.0/24", "10.100.0.0/24"));
    CHECK(!route(*b, endpoints[0], "fd00:77::/64")); transfer(loop, *da, *db, static_packet);
    std::cerr << "managed: static peer cannot bypass allocation on a managed tunnel\n";
    b->stop(); b.reset();
    cb.erase("address_clients"); cb["networks"].push_back("10.77.0.99/24"); cb["networks"].push_back("fd00:77::99/64");
    db = new MemoryDevice; b.reset(new Node(loop, parse_config(cb.dump()), std::unique_ptr<PacketDevice>(db), options())); b->start();
    until(loop, [&] { return route(a, endpoints[1], "10.99.0.0/24"); });
    spin(loop, 300); CHECK(!route(a, endpoints[1], "10.77.0.0/24")); transfer(loop, *da, *db, static_packet);
    CHECK(!imported(*db, "10.77.0.0/24", "10.78.0.0/24"));
    CHECK(imported(*db, "10.99.0.0/24", "10.100.0.0/24"));
    b->stop(); a.stop(); s->stop(); other.stop(); diagnostics = {};
    CHECK(da->exported.empty() && db->imported.empty());
}
}
int main(int argc, char** argv) {
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
    const auto pid = getpid();
#else
    const auto pid = GetCurrentProcessId();
#endif
    const auto state = std::string(argc > 1 ? argv[1] : "managed-node-state") + "." + std::to_string(pid) + ".json";
    try {
        SocketSystem sockets; run(state);
        std::remove(state.c_str()); std::remove((state + ".lock").c_str());
        std::remove((state + ".second").c_str()); std::remove((state + ".second.lock").c_str());
        std::cout << checks << " managed node checks passed\n"; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
