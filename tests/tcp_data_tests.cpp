#include "node.h"
#include "tcp_transport.h"
#include <algorithm>
#include <csignal>
#include <iostream>
#include <stdexcept>

namespace {
using Json = wire::Json;
unsigned checks = 0;
std::function<void()> diagnostics;
std::vector<Endpoint> known_endpoints;
const auto test_started = std::chrono::steady_clock::now();
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)

void phase(const std::string& label) {
    std::cerr << "[" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - test_started).count()
        << "ms] " << label << '\n';
}

template<class F> bool rejects(F operation) {
    try { operation(); return false; } catch (const std::exception&) { return true; }
}

void framing_tests() {
    const Json control{{"type", "ping"}, {"token", 7}};
    const Bytes payload{0, 0xff, 0, 0x7b, 0x7d, 10, 13};
    const auto encoded = wire::data_frame(payload);
    CHECK(encoded.size() == payload.size() + 4);
    CHECK((encoded[0] & 0x80) != 0);
    wire::Decoder split; Json message; Bytes data;
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        split.append(Bytes{encoded[i]});
        CHECK(split.next(message, data) == (i + 1 == encoded.size()));
    }
    CHECK(data == payload);
    CHECK(!split.next(message, data));

    auto coalesced = wire::frame(control);
    coalesced.insert(coalesced.end(), encoded.begin(), encoded.end());
    const auto next_control = wire::frame({{"type", "pong"}});
    coalesced.insert(coalesced.end(), next_control.begin(), next_control.end());
    wire::Decoder batch; batch.append(coalesced);
    CHECK(batch.next(message, data) && data.empty() && message == control);
    CHECK(batch.next(message, data) && data == payload);
    CHECK(batch.next(message, data) && data.empty() && message.at("type") == "pong");
    CHECK(!batch.next(message, data));

    wire::Decoder maximum;
    const Bytes large(wire::max_data_frame, 0xa5);
    const auto large_encoded = wire::data_frame(large);
    maximum.append(Bytes(large_encoded.begin(), large_encoded.begin() + 3));
    CHECK(!maximum.next(message, data));
    maximum.append(Bytes(large_encoded.begin() + 3, large_encoded.end()));
    CHECK(maximum.next(message, data) && data == large);
    CHECK(rejects([] { wire::data_frame(Bytes{}); }));
    CHECK(rejects([] { wire::data_frame(Bytes(wire::max_data_frame + 1)); }));
    CHECK(rejects([] {
        wire::Decoder invalid; Json j; Bytes b;
        invalid.append(Bytes{0x80, 0, 0, 0}); invalid.next(j, b);
    }));
    CHECK(rejects([] {
        wire::Decoder invalid; Json j; Bytes b;
        const auto n = static_cast<std::uint32_t>(wire::max_data_frame + 1);
        invalid.append(Bytes{static_cast<unsigned char>(0x80 | (n >> 24)),
            static_cast<unsigned char>(n >> 16), static_cast<unsigned char>(n >> 8), static_cast<unsigned char>(n)});
        invalid.next(j, b);
    }));
    CHECK(rejects([&] {
        wire::Decoder control_only; Json j; control_only.append(encoded); control_only.next(j);
    }));
    wire::Decoder decoder; decoder.append(wire::frame(control));
    CHECK(decoder.next(message) && message == control);
}

class MemoryDevice : public PacketDevice {
public:
    Receiver receiver;
    std::vector<Bytes> delivered;
    void start(Receiver value) override { receiver = std::move(value); }
    bool send(const Bytes& value) override { delivered.push_back(value); return true; }
    std::string name() const override { return "tcp-data-memory"; }
    void inject(const Bytes& value) { CHECK(static_cast<bool>(receiver)); receiver(value); }
};

void until(EventLoop& loop, const std::function<bool()>& condition, unsigned timeout = 15000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    while (!condition() && std::chrono::steady_clock::now() < deadline) {
        auto poll = loop.addTimer(std::chrono::milliseconds(10), [&](evutil_socket_t, short) { loop.breakLoop(); });
        loop.run();
    }
    if (!condition() && diagnostics) diagnostics();
    CHECK(condition());
}

std::vector<Endpoint> ports(EventLoop& loop, unsigned count, bool ipv6 = false) {
    std::vector<std::unique_ptr<UdpTransport>> udp;
    std::vector<std::unique_ptr<TcpListener>> tcp;
    std::vector<Endpoint> result;
    const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
    for (unsigned i = 0; i < 10000 && result.size() < count; ++i) {
        Endpoint endpoint; endpoint.ip = IpAddress::parse(ipv6 ? "::1" : "127.0.0.1");
        endpoint.port = static_cast<std::uint16_t>(20000 + (seed + i) % 10000);
        try {
            std::unique_ptr<UdpTransport> u(new UdpTransport(loop, endpoint, 1400, [](const Endpoint&, Bytes) {}));
            std::unique_ptr<TcpListener> t(new TcpListener(loop, endpoint, [](evutil_socket_t fd) { evutil_closesocket(fd); }));
            udp.push_back(std::move(u)); tcp.push_back(std::move(t)); result.push_back(endpoint);
        } catch (const std::exception&) {}
    }
    if (result.size() != count) throw std::runtime_error("cannot reserve TCP data test ports");
    std::sort(result.begin(), result.end());
    known_endpoints = result;
    return result;
}

Configure config(unsigned index, const std::vector<Endpoint>& endpoints, const std::vector<unsigned>& peers) {
    Json value{{"listen", {{"bind_address", endpoints[index].str()}}},
        {"networks", {"10.97.0." + std::to_string(index + 1) + "/24", "fd00:97::" + std::to_string(index + 1) + "/64"}},
        {"peers", Json::array()}};
    for (const auto peer : peers) value["peers"].push_back({{"endpoint", endpoints[peer].str()},
        {"shared_key", "tcp-data-test-key"}, {"networks", {"10.97.0.0/24", "fd00:97::/64"}}});
    return parse_config(value.dump());
}

NodeOptions options() {
    // Heartbeat also determines the E2E handshake retry interval. Keep its
    // production value for data tests; proxy hops and Windows TLS progress
    // must not be mistaken for a stalled handshake by an accelerated timer.
    NodeOptions value; value.tick_ms = 10; value.heartbeat_ms = 5000;
    value.failure_timeout_ms = 20000; value.handshake_timeout_ms = 10000; value.reconnect_ms = 100;
    return value;
}

Json route(Node& node, const Endpoint& endpoint, const std::string& network = "10.97.0.0/24") {
    const auto state = node.status();
    std::string identity;
    for (const auto& peer : state.at("peers")) if (peer.at("endpoint") == endpoint.str()) {
        const auto& identities = peer.at("identities");
        if (identities.is_object() && identities.count(network)) identity = identities.at(network).get<std::string>();
    }
    if (identity.empty()) for (std::size_t i = 0; i < known_endpoints.size(); ++i) if (known_endpoints[i] == endpoint) {
        identity = network.find(':') == std::string::npos ? "10.97.0." + std::to_string(i + 1) : "fd00:97::" + std::to_string(i + 1); break;
    }
    for (const auto& value : state.at("routes"))
        if (value.at("node") == identity && value.at("network") == network) return value;
    return nullptr;
}

std::uint64_t counter(Node& node, const std::string& name) {
    const auto values = node.status().at("counters");
    return values.count(name) ? values.at(name).get<std::uint64_t>() : 0;
}

bool settled(Node& node) {
    const auto state = node.status();
    if (state.at("pending_connections") != 0 || state.at("peers").empty()) return false;
    for (const auto& peer : state.at("peers")) if (peer.at("state") != 3) return false;
    return true;
}

std::string transport(Node& node, const Endpoint& endpoint) {
    const auto state = node.status();
    for (const auto& peer : state.at("peers")) if (peer.at("endpoint") == endpoint.str())
        return peer.at("transport").get<std::string>();
    return {};
}

std::string session(Node& node, const Endpoint& endpoint) {
    const auto state = node.status();
    std::string identity;
    for (const auto& peer : state.at("peers")) if (peer.at("endpoint") == endpoint.str()) {
        const auto& identities = peer.at("identities");
        if (identities.is_object() && identities.count("10.97.0.0/24")) identity = identities.at("10.97.0.0/24").get<std::string>();
    }
    if (identity.empty()) for (std::size_t i = 0; i < known_endpoints.size(); ++i) if (known_endpoints[i] == endpoint) { identity = "10.97.0." + std::to_string(i + 1); break; }
    for (const auto& value : state.at("end_sessions"))
        if (value.at("node") == identity && value.at("network") == "10.97.0.0/24" && value.at("ready") == true)
            return value.at("id").get<std::string>();
    return {};
}

void until_stable(EventLoop& loop, const std::vector<Node*>& nodes, const std::function<bool()>& condition) {
    std::string previous;
    auto last_change = std::chrono::steady_clock::now();
    until(loop, [&] {
        if (!condition()) { previous.clear(); last_change = std::chrono::steady_clock::now(); return false; }
        std::string generation;
        for (auto* node : nodes) generation += std::to_string(counter(*node, "peer_up")) + ":" +
            std::to_string(counter(*node, "peer_down")) + ";";
        if (generation != previous) { previous = generation; last_change = std::chrono::steady_clock::now(); }
        return std::chrono::steady_clock::now() - last_change >= std::chrono::milliseconds(150);
    });
}

Bytes packet(unsigned source, unsigned destination, unsigned flow, bool ipv6 = false, bool multicast = false) {
    Bytes bytes(100);
    if (ipv6) {
        bytes[0] = 0x60; bytes[5] = 60; bytes[6] = 17; bytes[7] = 64;
        const auto src = IpAddress::parse("fd00:97::" + std::to_string(source));
        const auto dst = IpAddress::parse(multicast ? "ff05::97" : "fd00:97::" + std::to_string(destination));
        std::copy(src.bytes.begin(), src.bytes.end(), bytes.begin() + 8);
        std::copy(dst.bytes.begin(), dst.bytes.end(), bytes.begin() + 24);
        bytes[40] = static_cast<unsigned char>(flow >> 8); bytes[41] = static_cast<unsigned char>(flow);
        bytes[42] = 0x12; bytes[43] = 0x34; bytes[45] = 60;
    } else {
        bytes[0] = 0x45; bytes[3] = 100; bytes[8] = 64; bytes[9] = 17;
        bytes[12] = 10; bytes[13] = 97; bytes[15] = static_cast<unsigned char>(source);
        bytes[16] = multicast ? 239 : 10; bytes[17] = 97; bytes[19] = static_cast<unsigned char>(destination);
        bytes[20] = static_cast<unsigned char>(flow >> 8); bytes[21] = static_cast<unsigned char>(flow);
        bytes[22] = 0x12; bytes[23] = 0x34; bytes[25] = 80;
    }
    bytes[99] = static_cast<unsigned char>(flow); return bytes;
}

void send_packet(EventLoop& loop, MemoryDevice& source, MemoryDevice& destination, const Bytes& bytes) {
    const auto before = destination.delivered.size(); source.inject(bytes);
    until(loop, [&] { return destination.delivered.size() == before + 1; });
    CHECK(destination.delivered.back() == bytes);
}

void queue_saturation_tests() {
    phase("queue saturation: setup");
    EventLoop loop; const auto endpoints = ports(loop, 2);
    auto ca = config(0, endpoints, {1}), cb = config(1, endpoints, {0});
    ca.peers[0].transport = "tcp";
    auto* da = new MemoryDevice; auto* db = new MemoryDevice;
    // Saturation deliberately blocks all event dispatch while injecting a
    // burst. Keep production liveness slack; the proxy tests above exercise
    // short-deadline expiry independently.
    Node a(loop, ca, std::unique_ptr<PacketDevice>(da), options());
    Node b(loop, cb, std::unique_ptr<PacketDevice>(db), options());
    diagnostics = [&] { std::cerr << a.status().dump(2) << '\n' << b.status().dump(2) << '\n'; };
    a.start(); b.start();
    until_stable(loop, {&a, &b}, [&] { return settled(a) && settled(b) && !route(a, endpoints[1]).is_null() && !route(b, endpoints[0]).is_null(); });
    phase("queue saturation: warm E2E session");
    send_packet(loop, *da, *db, packet(1, 2, 400));
    const auto ups = counter(a, "peer_up"), downs = counter(a, "peer_down");
    const auto before = db->delivered.size();
    const auto previous_drops = counter(a, "tcp_data_send_drop");
    const auto previous_session = session(a, endpoints[1]);
    auto maximum_packet = packet(1, 2, 401); maximum_packet.resize(1280, 0x6d);
    maximum_packet[2] = 5; maximum_packet[3] = 0;
    maximum_packet[24] = 4; maximum_packet[25] = 236;
    const unsigned sent = 1200;
    const auto start = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < sent; ++i) da->inject(maximum_packet);
    const auto enqueued = std::chrono::steady_clock::now();
    const auto dropped = counter(a, "tcp_data_send_drop") - previous_drops;
    std::cerr << "TCP bulk: enqueue " << std::chrono::duration_cast<std::chrono::milliseconds>(enqueued - start).count()
        << "ms, accepted " << sent - dropped << ", dropped " << dropped << '\n';
    CHECK(dropped > 0 && dropped < sent);
    until(loop, [&] { return db->delivered.size() == before + sent - dropped; });
    std::cerr << "TCP bulk: drain " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - enqueued).count() << "ms\n";
    CHECK(counter(a, "peer_up") == ups && counter(a, "peer_down") == downs);
    CHECK(settled(a) && settled(b) && session(a, endpoints[1]) == previous_session);
    send_packet(loop, *da, *db, packet(1, 2, 402));
    a.stop(); b.stop(); diagnostics = {};
    phase("queue saturation: done");
}

void mixed_and_reload_tests() {
    phase("mixed transports: setup");
    EventLoop loop; const auto endpoints = ports(loop, 4);
    std::vector<Configure> configs{config(0, endpoints, {1, 3}), config(1, endpoints, {0, 2}),
        config(2, endpoints, {1}), config(3, endpoints, {0})};
    // Keep this scenario mixed: the production default is TCP, so explicitly
    // start every adjacency in UDP before switching only A-B to TCP below.
    for (auto& value : configs) for (auto& peer : value.peers) peer.transport = "udp";
    std::vector<std::unique_ptr<Node>> nodes; std::vector<MemoryDevice*> devices;
    for (unsigned i = 0; i < configs.size(); ++i) {
        auto* device = new MemoryDevice; devices.push_back(device);
        nodes.emplace_back(new Node(loop, configs[i], std::unique_ptr<PacketDevice>(device), options()));
        nodes.back()->start();
    }
    diagnostics = [&] { for (const auto& node : nodes) std::cerr << node->status().dump(2) << '\n'; };
    auto converged = [&] {
        for (const auto& node : nodes) if (!settled(*node)) return false;
        return !route(*nodes[0], endpoints[2]).is_null() && !route(*nodes[2], endpoints[0]).is_null() &&
            !route(*nodes[0], endpoints[2], "fd00:97::/64").is_null();
    };
    const std::vector<Node*> all{nodes[0].get(), nodes[1].get(), nodes[2].get(), nodes[3].get()};
    until_stable(loop, all, converged);
    phase("mixed transports: establish unaffected E2E session");
    send_packet(loop, *devices[0], *devices[3], packet(1, 4, 11));
    const auto untouched_session = session(*nodes[0], endpoints[3]);
    const auto untouched_ups = counter(*nodes[3], "peer_up"), untouched_downs = counter(*nodes[3], "peer_down");
    CHECK(!untouched_session.empty());
    auto changed = nodes[0]->configuration(); changed.peers[0].transport = "tcp";
    const auto result = nodes[0]->apply_config(changed);
    phase("mixed transports: switch one peer to TCP");
    CHECK(result.at("ok") == true && result.at("mode") == "peers" && result.at("changed_peers") == 1);
    CHECK(session(*nodes[0], endpoints[3]) == untouched_session);
    until_stable(loop, all, [&] { return converged() && transport(*nodes[0], endpoints[1]) == "tcp" && transport(*nodes[1], endpoints[0]) == "tcp"; });
    CHECK(transport(*nodes[1], endpoints[2]) == "udp" && transport(*nodes[0], endpoints[3]) == "udp");
    CHECK(counter(*nodes[3], "peer_up") == untouched_ups && counter(*nodes[3], "peer_down") == untouched_downs);
    CHECK(session(*nodes[0], endpoints[3]) == untouched_session);
    CHECK(parse_config(serialize_config(nodes[0]->configuration())).peers[0].transport == "tcp");
    phase("mixed transports: bidirectional IPv4/IPv6 E2E");
    for (unsigned i = 0; i < 2; ++i) {
        send_packet(loop, *devices[0], *devices[2], packet(1, 3, 20 + i, i != 0));
        send_packet(loop, *devices[2], *devices[0], packet(3, 1, 30 + i, i != 0));
    }
    CHECK(devices[1]->delivered.empty());
    CHECK(nodes[1]->status().at("end_sessions").empty());
    CHECK(counter(*nodes[1], "unicast_forwarded") >= 4);
    CHECK(!session(*nodes[0], endpoints[2]).empty());
    const auto before = devices[2]->delivered.size();
    phase("mixed transports: burst and flooding");
    for (unsigned i = 0; i < 32; ++i) devices[0]->inject(packet(1, 3, 100 + i));
    until(loop, [&] { return devices[2]->delivered.size() == before + 32; });
    for (unsigned i = 0; i < 32; ++i)
        CHECK(std::find(devices[2]->delivered.begin() + before, devices[2]->delivered.end(), packet(1, 3, 100 + i)) != devices[2]->delivered.end());

    // All flood variants must cross TCP and UDP without reaching a node twice.
    const std::vector<Bytes> floods{packet(1, 255, 201), packet(1, 97, 202, false, true), packet(1, 97, 203, true, true)};
    for (const auto& flood : floods) {
        std::vector<std::size_t> sizes; for (const auto* device : devices) sizes.push_back(device->delivered.size());
        devices[0]->inject(flood);
        until(loop, [&] {
            for (unsigned i = 1; i < devices.size(); ++i) if (devices[i]->delivered.size() != sizes[i] + 1) return false;
            return true;
        });
        CHECK(devices[0]->delivered.size() == sizes[0]);
        for (unsigned i = 1; i < devices.size(); ++i) CHECK(devices[i]->delivered.back() == flood);
    }
    // Revert only A-B to UDP, preserving the independent A-D authorization and session.
    changed = nodes[0]->configuration(); changed.peers[0].transport = "udp";
    phase("mixed transports: switch one peer back to UDP");
    const auto reverted = nodes[0]->apply_config(changed);
    CHECK(reverted.at("ok") == true && reverted.at("mode") == "peers");
    until_stable(loop, all, [&] { return converged() && transport(*nodes[0], endpoints[1]) == "udp" && transport(*nodes[1], endpoints[0]) == "udp"; });
    CHECK(session(*nodes[0], endpoints[3]) == untouched_session);
    CHECK(counter(*nodes[3], "peer_up") == untouched_ups && counter(*nodes[3], "peer_down") == untouched_downs);
    send_packet(loop, *devices[0], *devices[2], packet(1, 3, 301));
    for (auto& node : nodes) node->stop(); diagnostics = {};
    phase("mixed transports: done");
}

void authentication_tests() {
    EventLoop loop; const auto endpoints = ports(loop, 2);
    auto ca = config(0, endpoints, {1}), cb = config(1, endpoints, {0});
    ca.peers[0].transport = "tcp"; cb.peers[0].transport = "tcp"; cb.peers[0].shared_key = "wrong-tcp-key";
    Node a(loop, ca, std::unique_ptr<PacketDevice>(new MemoryDevice), options());
    Node b(loop, cb, std::unique_ptr<PacketDevice>(new MemoryDevice), options());
    a.start(); b.start();
    until(loop, [&] { return counter(a, "control_rejected") + counter(b, "control_rejected") > 0; });
    CHECK(a.status().at("routes").empty() && b.status().at("routes").empty());
    CHECK(counter(a, "peer_up") == 0 && counter(b, "peer_up") == 0);
    CHECK(a.status().at("end_sessions").empty() && b.status().at("end_sessions").empty());
    a.stop(); b.stop();
    const auto config_text = serialize_config(ca);
    auto invalid = Json::parse(config_text); invalid["peers"][0]["transport"] = "invalid";
    CHECK(rejects([&] { parse_config(invalid.dump()); }));
    invalid["peers"][0]["transport"] = 123;
    CHECK(rejects([&] { parse_config(invalid.dump()); }));
}
}

int main() {
    try {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        SocketSystem sockets;
        phase("framing tests");
        framing_tests();
        queue_saturation_tests();
        mixed_and_reload_tests();
        phase("authentication tests");
        authentication_tests();
        std::cout << "Passed " << checks << " TCP data transport checks\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
