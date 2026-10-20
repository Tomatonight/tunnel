#include "node.h"
#include "tls.h"
#include "tcp_transport.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <csignal>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#endif
namespace {
unsigned checks = 0;
std::function<void()> diagnostics;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)
void handshake(TlsChannel& a, TlsChannel& b) {
    a.advance();
    for (unsigned i = 0; i < 20 && (!a.ready() || !b.ready()); ++i) {
        b.feed(a.drain()); a.feed(b.drain());
    }
    CHECK(a.ready() && b.ready());
}
void tls_tests() {
    TlsChannel a(true, "a|b", [](const std::string&) { return "same-secret"; });
    TlsChannel b(false, "", [](const std::string& id) { return id == "a|b" ? "same-secret" : ""; });
    handshake(a, b);
    auto left = a.session(CryptoScope::Link, "a|b"); auto right = b.session(CryptoScope::Link, "a|b"); Bytes plain;
    CHECK(left->id() == right->id()); CHECK(right->open(left->seal(Bytes{1,2,3}), plain)); CHECK(plain == Bytes({1,2,3}));
    auto long_a = a.session(CryptoScope::Link, std::string(4096, 'x'));
    auto long_b = b.session(CryptoScope::Link, std::string(4096, 'x'));
    CHECK(long_b->open(long_a->seal(Bytes{8}), plain));
    auto wrong_context = b.session(CryptoScope::Link, "different-network-context");
    CHECK(!wrong_context->open(left->seal(Bytes{9}), plain));
    a.write(Bytes{4,5}); b.feed(a.drain()); CHECK(b.read() == Bytes({4,5}));
    bool rejected = false;
    try {
        TlsChannel x(true, "a|b", [](const std::string&) { return "wrong-secret"; });
        TlsChannel y(false, "", [](const std::string&) { return "same-secret"; }); handshake(x, y);
    } catch (const std::exception&) { rejected = true; }
    CHECK(rejected);
    IdentityKey ia, ib, other;
    TlsChannel e(true, ia, ib.public_key()), f(false, ib, ia.public_key()); handshake(e, f);
    auto ec = e.session(CryptoScope::EndToEnd, "network|a|b"); auto fc = f.session(CryptoScope::EndToEnd, "network|a|b");
    CHECK(fc->open(ec->seal(Bytes{6,7}), plain)); CHECK(plain == Bytes({6,7}));
    rejected = false;
    try { TlsChannel x(true, ia, other.public_key()), y(false, ib, ia.public_key()); handshake(x, y); }
    catch (const std::exception&) { rejected = true; }
    CHECK(rejected);
    wire::Decoder decoder; auto frame = wire::frame({{"type", "ping"}}); wire::Json message;
    for (std::size_t i = 0; i < frame.size(); ++i) { decoder.append(Bytes{frame[i]}); CHECK(decoder.next(message) == (i + 1 == frame.size())); }
    CHECK(message.at("type") == "ping");
    rejected = false; try { decoder.append(Bytes{0xff,0xff,0xff,0xff}); decoder.next(message); } catch (...) { rejected = true; }
    CHECK(rejected);
}
class MemoryDevice : public PacketDevice {
public:
    Receiver receiver;
    std::vector<Bytes> delivered;
    std::vector<ImportedRoute> imported;
    std::vector<AdvertisedRoute> exported;
    bool reject_imports = false, reject_exports = false;
    void set_routes(const std::vector<ImportedRoute>& routes) override {
        if (reject_imports && !routes.empty()) throw std::runtime_error("test route conflict");
        imported = routes;
    }
    void set_exports(const std::vector<AdvertisedRoute>& routes) override {
        if (reject_exports && !routes.empty()) throw std::runtime_error("test NAT unavailable");
        exported = routes;
    }
    void start(Receiver r) override { receiver = std::move(r); }
    bool send(const Bytes& b) override { delivered.push_back(b); return true; }
    std::string name() const override { return "memory-test-device"; }
    void inject(const Bytes& b) { if (receiver) receiver(b); }
};
void spin(EventLoop& loop, unsigned milliseconds) {
    auto done = loop.addTimer(std::chrono::milliseconds(milliseconds), [&](evutil_socket_t, short) { loop.breakLoop(); });
    loop.run();
}
void until(EventLoop& loop, std::function<bool()> predicate, unsigned timeout = 10000) {
    auto poll = loop.addTimer(std::chrono::milliseconds(10), [&](evutil_socket_t, short) { if (predicate()) loop.breakLoop(); }, true);
    auto deadline = loop.addTimer(std::chrono::milliseconds(timeout), [&](evutil_socket_t, short) { loop.breakLoop(); });
    loop.run(); if (!predicate() && diagnostics) diagnostics(); CHECK(predicate());
}
void until_both(EventLoop& left, EventLoop& right, std::function<bool()> predicate, unsigned timeout = 10000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        spin(left, 5); spin(right, 5);
    }
    CHECK(predicate());
}
Bytes packet(unsigned source, unsigned destination, unsigned flow = 1, bool v6 = false, bool multicast = false) {
    Bytes p(100);
    if (v6) {
        p[0] = 0x60; p[5] = 60; p[6] = 17; p[7] = 64;
        auto src = IpAddress::parse("fd00:77::" + std::to_string(source));
        auto dst = IpAddress::parse(multicast ? "ff05::123" : "fd00:77::" + std::to_string(destination));
        std::copy(src.bytes.begin(), src.bytes.end(), p.begin() + 8); std::copy(dst.bytes.begin(), dst.bytes.end(), p.begin() + 24);
        p[40] = flow >> 8; p[41] = flow; p[42] = 0x12; p[43] = 0x34; p[45] = 60;
    } else {
        p[0] = 0x45; p[3] = 100; p[8] = 64; p[9] = 17;
        p[12] = 10; p[13] = 77; p[15] = source;
        p[16] = multicast ? 239 : 10; p[17] = 77; p[19] = destination;
        p[20] = flow >> 8; p[21] = flow; p[22] = 0x12; p[23] = 0x34; p[25] = 80;
    }
    p[99] = 0xaa; return p;
}
Configure config_for(unsigned i, const std::vector<Endpoint>& addresses, const std::vector<unsigned>& peers, bool v6 = true) {
    Configure c; c.listen.enabled = true; c.listen.address = c.listen.bind_address = addresses.at(i);
    NetworkConfig n; n.tunnel = Network::parse("10.77.0.0/24"); n.tunnel_ip = IpAddress::parse("10.77.0." + std::to_string(i + 1));
    c.networks.push_back(n);
    if (v6) { n.tunnel = Network::parse("fd00:77::/64"); n.tunnel_ip = IpAddress::parse("fd00:77::" + std::to_string(i + 1)); c.networks.push_back(n); }
    c.listen.networks = c.networks;
    for (auto p : peers) { PeerConfig peer; peer.address = addresses.at(p); peer.shared_key = "test-only-link-" + std::to_string(std::min(i,p)) + "-" + std::to_string(std::max(i,p)); peer.networks = c.networks; c.peers.push_back(peer); }
    return c;
}
std::vector<Endpoint> ports(EventLoop& loop, unsigned count, bool v6 = false) {
    std::vector<std::unique_ptr<UdpTransport>> reservations; std::vector<Endpoint> result;
    std::vector<std::unique_ptr<TcpListener>> tcp_reservations;
    Endpoint bind; bind.ip = IpAddress::parse(v6 ? "::1" : "127.0.0.1");
    // Avoid default ephemeral ranges: the first Node starts dialing before all
    // later listeners exist, so a temporary TCP source must not steal their port.
    const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
    for (unsigned i = 0; i < 10000 && result.size() < count; ++i) {
        bind.port = static_cast<std::uint16_t>(20000 + (seed + i) % 10000);
        try {
            std::unique_ptr<UdpTransport> udp(new UdpTransport(loop, bind, 1400, [](const Endpoint&, Bytes) {}));
            std::unique_ptr<TcpListener> tcp(new TcpListener(loop, bind, [](evutil_socket_t fd) { evutil_closesocket(fd); }));
            reservations.push_back(std::move(udp)); tcp_reservations.push_back(std::move(tcp)); result.push_back(bind);
        } catch (const std::exception&) {} // Already used by another local process.
    }
    if (result.size() != count) throw std::runtime_error("no free test TCP/UDP port pairs");
    return result;
}
wire::Json find_route(Node& node, const Endpoint& destination, const std::string& network = "10.77.0.0/24") {
    const auto status = node.status();
    for (const auto& r : status.at("routes")) if (r.at("node") == destination.str() && r.at("network") == network) return r;
    return nullptr;
}
std::uint64_t counter(Node& node, const std::string& key) { const auto c = node.status().at("counters"); return c.count(key) ? c.at(key).get<std::uint64_t>() : 0; }
NodeOptions fast_options() {
    NodeOptions o; o.tick_ms = 10; o.heartbeat_ms = 100; o.failure_timeout_ms = 2000;
    o.handshake_timeout_ms = 5000; o.reconnect_ms = 100;
    o.log = [](const std::string& text) { std::cerr << text << '\n'; }; return o;
}
void subnet_runtime_tests() {
    EventLoop loop; auto addresses = ports(loop, 4);
    auto subnet_options = fast_options();
    // This test exercises routing and explicit shutdown, not heartbeat expiry.
    // Leave production-sized slack for Windows TLS setup between event-loop runs.
    subnet_options.failure_timeout_ms = 20000; subnet_options.handshake_timeout_ms = 10000;
    std::vector<Configure> configs{config_for(0, addresses, {1}, false), config_for(1, addresses, {0,2,3}, false),
        config_for(2, addresses, {1}, false), config_for(3, addresses, {1}, false)};
    AdvertisedRoute advertised; advertised.tunnel = Network::parse("10.77.0.0/24");
    advertised.prefix = Network::parse("10.78.0.0/24"); advertised.snat = true;
    configs[2].advertise_routes.push_back(advertised); configs[3].advertise_routes.push_back(advertised);
    std::vector<std::unique_ptr<Node>> nodes; std::vector<MemoryDevice*> devices;
    for (unsigned i = 0; i < 4; ++i) {
        auto* d = new MemoryDevice; devices.push_back(d);
        nodes.emplace_back(new Node(loop, configs[i], std::unique_ptr<PacketDevice>(d), subnet_options)); nodes.back()->start();
    }
    auto gateway = [&]() -> std::string {
        const auto status = nodes[0]->status();
        for (const auto& r : status.at("subnet_routes"))
            if (r.at("state") == "active") return r.at("gateway").get<std::string>();
        return {};
    };
    diagnostics = [&] { for (const auto& node : nodes) std::cerr << node->status().dump(2) << '\n'; };
    std::cerr << "subnet: converge\n";
    auto converged = [&] {
        for (const auto& node : nodes) {
            const auto status = node->status();
            if (status.at("pending_connections") != 0) return false;
            for (const auto& peer : status.at("peers")) if (peer.at("state") != 3) return false;
        }
        return !gateway().empty() && !find_route(*nodes[0], addresses[2]).is_null() && !find_route(*nodes[0], addresses[3]).is_null();
    };
    until(loop, converged);
    spin(loop, 200); until(loop, converged);
    CHECK(devices[0]->imported.size() == 1 && devices[1]->imported.size() == 1);
    CHECK(devices[2]->imported.empty() && devices[3]->imported.empty());
    CHECK(devices[2]->exported.size() == 1 && devices[3]->exported.size() == 1);
    const unsigned chosen = gateway() == addresses[2].str() ? 2 : 3, backup = chosen == 2 ? 3 : 2;
    auto request = packet(1,20,4001); request[17] = 78;
    std::cerr << "subnet: request\n";
    devices[0]->inject(request);
    until(loop, [&] { return devices[chosen]->delivered.size() == 1; });
    CHECK(devices[chosen]->delivered[0] == request && devices[backup]->delivered.empty());
    CHECK(devices[1]->delivered.empty() && counter(*nodes[1], "unicast_forwarded") > 0);
    auto response = request;
    for (unsigned i = 0; i < 4; ++i) std::swap(response[12+i], response[16+i]);
    std::swap(response[20], response[22]); std::swap(response[21], response[23]);
    devices[chosen]->inject(response);
    std::cerr << "subnet: reply\n";
    until(loop, [&] { return devices[0]->delivered.size() == 1; });
    CHECK(devices[0]->delivered[0] == response);
    auto unsolicited = response; unsolicited[21] ^= 1;
    devices[chosen]->inject(unsolicited); devices[backup]->inject(response);
    auto spoofed = request; spoofed[13] = 78; devices[0]->inject(spoofed);
    spin(loop, 100);
    CHECK(devices[0]->delivered.size() == 1 && devices[chosen]->delivered.size() == 1);
    CHECK(counter(*nodes[chosen], "subnet_unsolicited_drop") > 0);
    CHECK(counter(*nodes[backup], "subnet_unsolicited_drop") > 0);
    nodes[chosen]->stop();
    std::cerr << "subnet: failover\n";
    until(loop, [&] { return gateway() == addresses[backup].str(); });
    auto new_request = packet(1,20,4002); new_request[17] = 78; devices[0]->inject(new_request);
    until(loop, [&] { return devices[backup]->delivered.size() == 1; });
    CHECK(devices[backup]->delivered[0] == new_request);
    nodes[backup]->stop(); until(loop, [&] { return gateway().empty() && devices[0]->imported.empty(); });
    CHECK(!find_route(*nodes[0], addresses[1]).is_null());
    devices[0]->inject(packet(1,2,4003)); until(loop, [&] { return devices[1]->delivered.size() == 1; });
    for (auto& node : nodes) node->stop();
    diagnostics = {};

    // Failed NAT preparation must never be announced as a usable export.
    EventLoop failed_loop; auto failed_addresses = ports(failed_loop, 2);
    auto a = config_for(0, failed_addresses, {1}, false), b = config_for(1, failed_addresses, {0}, false);
    b.advertise_routes.push_back(advertised);
    auto* da = new MemoryDevice; auto* db = new MemoryDevice; db->reject_exports = true;
    Node left(failed_loop, a, std::unique_ptr<PacketDevice>(da), subnet_options);
    Node right(failed_loop, b, std::unique_ptr<PacketDevice>(db), subnet_options); left.start(); right.start();
    until(failed_loop, [&] { return !find_route(left, failed_addresses[1]).is_null(); });
    spin(failed_loop, 50);
    CHECK(left.status().at("subnet_routes").empty() && da->imported.empty());
    CHECK(!right.status().at("local_exports")[0].at("active").get<bool>());
    CHECK(right.status().at("local_exports")[0].at("error") == "test NAT unavailable");
    left.stop(); right.stop();
    db->reject_exports = false; da->reject_imports = true;
    left.start(); right.start();
    until(failed_loop, [&] { return !left.status().at("subnet_routes").empty(); });
    CHECK(left.status().at("subnet_routes")[0].at("state") == "error" && da->imported.empty());
    CHECK(!find_route(left, failed_addresses[1]).is_null());
    left.stop(); da->reject_imports = false; left.start();
    until(failed_loop, [&] { return !da->imported.empty(); });
    CHECK(left.status().at("subnet_routes")[0].at("state") == "active");
    left.stop(); right.stop();
}
void mesh_tests() {
    EventLoop loop; auto addresses = ports(loop, 4);
    std::sort(addresses.begin(), addresses.end());
    CHECK(addresses[0] < addresses[3]); // A always initiates TLS, including the immediate D-restart send.
    std::vector<Configure> configs{config_for(0, addresses, {1,2}), config_for(1, addresses, {0,3}),
        config_for(2, addresses, {0,3}, false), config_for(3, addresses, {1,2})};
    std::vector<std::unique_ptr<Node>> nodes; std::vector<MemoryDevice*> devices;
    for (unsigned i = 0; i < 4; ++i) {
        auto* d = new MemoryDevice; devices.push_back(d);
        nodes.emplace_back(new Node(loop, configs[i], std::unique_ptr<PacketDevice>(d), fast_options())); nodes.back()->start();
    }
    try {
    std::cerr << "mesh: converge\n";
    until(loop, [&] {
        for (const auto& n : nodes) {
            const auto s = n->status();
            if (s.at("pending_connections") != 0) return false;
            for (const auto& p : s.at("peers")) if (p.at("state") != 3) return false;
        }
        auto r = find_route(*nodes[0], addresses[3]); return !r.is_null() && r.at("next_hops").size() == 2;
    });
    spin(loop, 200);
    std::cerr << "mesh: first end-to-end packet\n";
    auto first = packet(1,4); devices[0]->inject(first);
    until(loop, [&] { return devices[3]->delivered.size() == 1; }); CHECK(devices[3]->delivered.back() == first);
    CHECK(devices[1]->delivered.empty() && devices[2]->delivered.empty());
    for (unsigned flow = 2; flow < 42; ++flow) devices[0]->inject(packet(1,4,flow));
    until(loop, [&] { return devices[3]->delivered.size() == 41; });
    CHECK(counter(*nodes[1], "unicast_forwarded") > 0 && counter(*nodes[2], "unicast_forwarded") > 0);
    std::cerr << "mesh: reverse and flooding\n";
    devices[3]->inject(packet(4,1)); until(loop, [&] { return devices[0]->delivered.size() == 1; });
    const auto old_key = nodes[3]->public_key();
    auto sessions = nodes[0]->status().at("end_sessions"); CHECK(sessions.size() == 1); const auto session_id = sessions[0].at("id");
    std::vector<std::size_t> sizes; for (auto* d : devices) sizes.push_back(d->delivered.size());
    devices[0]->inject(packet(1,255)); spin(loop, 250);
    CHECK(devices[0]->delivered.size() == sizes[0]);
    for (unsigned i = 1; i < 4; ++i) CHECK(devices[i]->delivered.size() == sizes[i] + 1);
    CHECK(counter(*nodes[3], "rpf_drop") > 0);
    for (unsigned i = 0; i < 4; ++i) sizes[i] = devices[i]->delivered.size();
    devices[0]->inject(packet(1,9,1,false,true)); spin(loop, 250);
    for (unsigned i = 1; i < 4; ++i) CHECK(devices[i]->delivered.size() == sizes[i] + 1);
    const auto c_before = devices[2]->delivered.size(), d_before = devices[3]->delivered.size();
    devices[0]->inject(packet(1,4,1,true)); until(loop, [&] { return devices[3]->delivered.size() == d_before + 1; });
    CHECK(devices[2]->delivered.size() == c_before);
    devices[0]->inject(packet(1,4,1,true,true)); spin(loop, 250);
    CHECK(devices[3]->delivered.size() == d_before + 2); CHECK(devices[2]->delivered.size() == c_before);
    const auto invalid_before = counter(*nodes[0], "invalid_tun_packet");
    devices[0]->inject(packet(2,4)); auto oversized = first; oversized.resize(1281); devices[0]->inject(oversized);
    CHECK(counter(*nodes[0], "invalid_tun_packet") == invalid_before + 2);
    std::cerr << "mesh: failover and restart\n";
    nodes[1]->stop();
    until(loop, [&] { auto r = find_route(*nodes[0], addresses[3]); return !r.is_null() && r.at("next_hops").size() == 1 && r.at("next_hops")[0] == addresses[2].str(); });
    CHECK(find_route(*nodes[0], addresses[3]).at("key") == wire::hex(old_key));
    const auto after_failure = nodes[0]->status();
    for (const auto& s : after_failure.at("end_sessions")) if (s.at("network") == "10.77.0.0/24") CHECK(s.at("id") == session_id);
    auto count = devices[3]->delivered.size(); devices[0]->inject(first);
    until(loop, [&] { return devices[3]->delivered.size() == count + 1; });
    until(loop, [&] { return find_route(*nodes[0], addresses[3], "fd00:77::/64").is_null(); });
    nodes[3]->stop(); until(loop, [&] { return find_route(*nodes[0], addresses[3]).is_null(); });
    CHECK(nodes[0]->status().at("end_sessions").empty());
    nodes[3].reset(); devices[3] = new MemoryDevice;
    nodes[3].reset(new Node(loop, configs[3], std::unique_ptr<PacketDevice>(devices[3]), fast_options()));
    CHECK(nodes[3]->public_key() != old_key); nodes[3]->start();
    // A route can first arrive through the nonpreferred simultaneous TCP
    // connection. Replacing that connection correctly withdraws its routes
    // and queued datagrams. Wait for bidirectional convergence and a quiet
    // connection generation before this one-shot UDP assertion; handshake
    // retry behavior is exercised separately below.
    std::string restart_generation;
    auto restart_changed = std::chrono::steady_clock::now();
    until(loop, [&] {
        const auto forward = find_route(*nodes[0], addresses[3]);
        const auto reverse = find_route(*nodes[3], addresses[0]);
        if (forward.is_null() || reverse.is_null() || forward.at("key") != wire::hex(nodes[3]->public_key()) ||
                reverse.at("key") != wire::hex(nodes[0]->public_key()) ||
                find_route(*nodes[2], addresses[3]).is_null() || find_route(*nodes[3], addresses[2]).is_null()) {
            restart_generation.clear(); restart_changed = std::chrono::steady_clock::now(); return false;
        }
        std::string generation;
        for (const auto i : {0, 2, 3}) generation += std::to_string(counter(*nodes[i], "peer_up")) + ":" +
            std::to_string(counter(*nodes[i], "peer_down")) + ";";
        if (generation != restart_generation) { restart_generation = generation; restart_changed = std::chrono::steady_clock::now(); }
        return std::chrono::steady_clock::now() - restart_changed >= std::chrono::milliseconds(300);
    });
    devices[0]->inject(first); until(loop, [&] { return devices[3]->delivered.size() == 1; });
    const auto stable = nodes[0]->public_key(); nodes[0]->reset_links();
    until(loop, [&] { return !find_route(*nodes[0], addresses[3]).is_null(); }); CHECK(nodes[0]->public_key() == stable);
    for (auto& node : nodes) node->stop();
    } catch (...) {
        for (const auto& n : nodes) if (n) std::cerr << n->status().dump(2) << '\n';
        throw;
    }
}
void handshake_retry_tests() {
    std::cerr << "e2e: stalled initiator retries without losing the queued packet\n";
    EventLoop left, right; auto addresses = ports(left, 2);
    std::sort(addresses.begin(), addresses.end()); CHECK(addresses[0] < addresses[1]);
    const auto ca = config_for(0, addresses, {1}), cb = config_for(1, addresses, {0});
    auto* da = new MemoryDevice; auto* db = new MemoryDevice;
    auto options = fast_options(); options.failure_timeout_ms = 5000;
    Node a(left, ca, std::unique_ptr<PacketDevice>(da), options);
    Node b(right, cb, std::unique_ptr<PacketDevice>(db), options);
    a.start(); b.start();
    until_both(left, right, [&] {
        return !find_route(a, addresses[1]).is_null() && !find_route(b, addresses[0]).is_null() &&
            a.status().at("pending_connections") == 0 && b.status().at("pending_connections") == 0;
    });
    const auto original = packet(1, 2, 51);
    da->inject(original);
    const auto first_id = a.status().at("end_sessions")[0].at("id");
    // Both routes remain present, but B cannot consume the first TLS flight or
    // answer it while only A's event loop runs. This deterministically forces
    // a fresh handshake before either peer's 5-second liveness timeout.
    spin(left, 650);
    CHECK(db->delivered.empty());
    CHECK(!find_route(a, addresses[1]).is_null());
    CHECK(counter(a, "e2e_handshake_retried") >= 1);
    CHECK(a.status().at("end_sessions")[0].at("id") != first_id);
    // The old TLS flight is still queued in TCP. Resuming B processes old and
    // new attempts; stale responses must not corrupt the current TLS state.
    until_both(left, right, [&] { return db->delivered.size() == 1; });
    CHECK(db->delivered.front() == original);
    const auto reverse = packet(2, 1, 52); db->inject(reverse);
    until_both(left, right, [&] { return da->delivered.size() == 1; });
    CHECK(da->delivered.front() == reverse && db->delivered.size() == 1);
    CHECK(counter(a, "pending_drop") == 0 && counter(b, "pending_drop") == 0);
    a.stop(); b.stop();
}
void rejection_and_ipv6_tests() {
    EventLoop loop; const auto addresses = ports(loop, 2, true);
    auto ca = config_for(0, addresses, {1}); auto cb = config_for(1, addresses, {0});
    cb.peers[0].shared_key = "different-key";
    auto* da = new MemoryDevice; auto* db = new MemoryDevice;
    Node a(loop, ca, std::unique_ptr<PacketDevice>(da), fast_options());
    std::unique_ptr<Node> b(new Node(loop, cb, std::unique_ptr<PacketDevice>(db), fast_options()));
    a.start(); b->start(); spin(loop, 800);
    CHECK(a.status().at("routes").empty()); CHECK(b->status().at("routes").empty());
    CHECK(counter(a, "control_rejected") + counter(*b, "control_rejected") > 0);
    b->stop(); b.reset(); cb.peers[0].shared_key = ca.peers[0].shared_key;
    // Inbound disabled still permits outgoing authenticated TCP and shared UDP.
    cb.listen.enabled = false; db = new MemoryDevice;
    b.reset(new Node(loop, cb, std::unique_ptr<PacketDevice>(db), fast_options())); b->start();
    until(loop, [&] { return !find_route(a, addresses[1]).is_null(); });
    da->inject(packet(1,2)); until(loop, [&] { return db->delivered.size() == 1; });
    da->inject(packet(1,2,1,true)); until(loop, [&] { return db->delivered.size() == 2; });
    a.stop(); b->stop();
}
void lifecycle_tests() {
    EventLoop loop; const auto addresses = ports(loop, 2);
    auto ca = config_for(0, addresses, {1}); auto cb = config_for(1, addresses, {0});
    cb.listen.enabled = false;
    auto* da = new MemoryDevice; auto* db = new MemoryDevice;
    auto options = fast_options(); options.session_lifetime_ms = 3000;
    options.identity = std::make_shared<IdentityKey>();
    const auto identity = options.identity->public_key();
    Node a(loop, ca, std::unique_ptr<PacketDevice>(da), options);
    auto remote_options = options; remote_options.identity.reset();
    Node b(loop, cb, std::unique_ptr<PacketDevice>(db), remote_options);
    a.start(); b.start();
    until(loop, [&] { return !find_route(a, addresses[1]).is_null() && !find_route(b, addresses[0]).is_null() &&
        a.status().at("pending_connections") == 0 && b.status().at("pending_connections") == 0; });
    da->inject(packet(1,2)); until(loop, [&] { return db->delivered.size() == 1; });
    const auto id = a.status().at("end_sessions")[0].at("id");
    const auto ups = counter(a, "peer_up");
    until(loop, [&] { return counter(a, "peer_up") > ups && !find_route(b, addresses[0]).is_null(); });
    CHECK(a.public_key() == identity);
    da->inject(packet(1,2)); until(loop, [&] { return db->delivered.size() == 2; });
    CHECK(a.status().at("end_sessions")[0].at("id") != id);
    a.stop(); b.stop();
    Node replacement(loop, ca, std::unique_ptr<PacketDevice>(new MemoryDevice), options);
    CHECK(replacement.public_key() == identity); // Android host-owned process key.
#ifndef _WIN32
    int descriptors[2]; CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, descriptors) == 0);
    const int transferred = descriptors[0];
    auto tun_config = ca; tun_config.device_backend = "tun";
    auto tun = open_tun(loop, tun_config, "", transferred);
    CHECK((fcntl(transferred, F_GETFL) & O_NONBLOCK) != 0);
    Bytes received; tun->start([&](Bytes bytes) { received = std::move(bytes); });
    const auto ip = packet(1,2);
    CHECK(write(descriptors[1], ip.data(), ip.size()) == static_cast<ssize_t>(ip.size()));
    until(loop, [&] { return received == ip; });
    CHECK(tun->send(ip)); Bytes response(ip.size());
    CHECK(read(descriptors[1], response.data(), response.size()) == static_cast<ssize_t>(ip.size()));
    CHECK(response == ip); tun.reset();
    CHECK(fcntl(transferred, F_GETFD) == -1); close(descriptors[1]);
#endif
}
}
int main() {
    try {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        SocketSystem sockets; tls_tests(); mesh_tests(); handshake_retry_tests(); rejection_and_ipv6_tests(); lifecycle_tests(); subnet_runtime_tests();
        std::cout << "Passed " << checks << " runtime checks\n"; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
