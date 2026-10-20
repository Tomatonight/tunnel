#include "node.h"
#include "tcp_transport.h"
#include <algorithm>
#include <cstdio>
#include <csignal>
#include <iostream>
#include <stdexcept>

namespace {
using Json = wire::Json;
unsigned checks = 0;
std::function<void()> diagnostics;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)
struct Record {
    Configure config;
    PacketDevice::Receiver receive;
    std::vector<Bytes> delivered;
    std::vector<ImportedRoute> imported;
    std::vector<AdvertisedRoute> exported;
    bool destroyed = false, fail_start = false;
};
struct Factory {
    unsigned live = 0, peak = 0, calls = 0, rejected_mtu = 0, bad_start_mtu = 0;
    bool reject_all = false;
    std::vector<std::shared_ptr<Record>> records;
    std::shared_ptr<Record> current() { return records.back(); }
};
class MemoryDevice : public PacketDevice {
    std::shared_ptr<Factory> owner_;
    std::shared_ptr<Record> record_;
public:
    MemoryDevice(std::shared_ptr<Factory> owner, const Configure& config) : owner_(owner), record_(new Record) {
        record_->config = config; record_->fail_start = config.tun_mtu == owner_->bad_start_mtu;
        owner_->records.push_back(record_); ++owner_->live; owner_->peak = std::max(owner_->peak, owner_->live);
    }
    ~MemoryDevice() { record_->receive = {}; record_->destroyed = true; --owner_->live; }
    void start(Receiver receiver) override {
        if (receiver && record_->fail_start) throw std::runtime_error("injected device start failure");
        record_->receive = std::move(receiver);
    }
    bool send(const Bytes& bytes) override { record_->delivered.push_back(bytes); return true; }
    void set_networks(const std::vector<NetworkConfig>& value) override { record_->config.networks = value; }
    void set_routes(const std::vector<ImportedRoute>& value) override { record_->imported = value; }
    void set_exports(const std::vector<AdvertisedRoute>& value) override { record_->exported = value; }
    std::string name() const override { return "reload-memory-device"; }
};
std::unique_ptr<PacketDevice> make_device(const std::shared_ptr<Factory>& state, const Configure& config) {
    ++state->calls;
    if (state->reject_all || config.tun_mtu == state->rejected_mtu) throw std::runtime_error("injected device factory failure");
    return std::unique_ptr<PacketDevice>(new MemoryDevice(state, config));
}
NodeOptions options(const std::shared_ptr<Factory>& factory) {
    NodeOptions result; result.tick_ms = 10; result.heartbeat_ms = 100; result.failure_timeout_ms = 20000;
    result.handshake_timeout_ms = 10000; result.reconnect_ms = 100;
    result.device_factory = [factory](const Configure& config) { return make_device(factory, config); };
    return result;
}
void until(EventLoop& loop, const std::function<bool()>& condition, unsigned timeout = 12000) {
    auto poll = loop.addTimer(std::chrono::milliseconds(10), [&](evutil_socket_t, short) { if (condition()) loop.breakLoop(); }, true);
    auto deadline = loop.addTimer(std::chrono::milliseconds(timeout), [&](evutil_socket_t, short) { loop.breakLoop(); });
    loop.run(); if (!condition() && diagnostics) diagnostics(); CHECK(condition());
}
std::vector<Endpoint> ports(EventLoop& loop, unsigned count) {
    std::vector<std::unique_ptr<UdpTransport>> udp;
    std::vector<std::unique_ptr<TcpListener>> tcp;
    std::vector<Endpoint> result;
    const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
    for (unsigned i = 0; i < 10000 && result.size() < count; ++i) {
        Endpoint address; address.ip = IpAddress::parse("127.0.0.1"); address.port = 20000 + (seed + i) % 10000;
        try {
            std::unique_ptr<UdpTransport> u(new UdpTransport(loop, address, 1400, [](const Endpoint&, Bytes) {}));
            std::unique_ptr<TcpListener> t(new TcpListener(loop, address, [](evutil_socket_t fd) { evutil_closesocket(fd); }));
            udp.push_back(std::move(u)); tcp.push_back(std::move(t)); result.push_back(address);
        } catch (const std::exception&) {}
    }
    if (result.size() != count) throw std::runtime_error("cannot reserve reload test ports");
    return result;
}
Configure config(unsigned index, const std::vector<Endpoint>& endpoints, const std::vector<unsigned>& peers) {
    Json value{{"address", endpoints[index].str()}, {"listen", {{"bind_address", endpoints[index].str()}}},
        {"networks", {"10.91.0." + std::to_string(index + 1) + "/24", "10.92.0." + std::to_string(index + 1) + "/24"}}, {"peers", Json::array()}};
    for (const auto peer : peers) value["peers"].push_back({{"address", endpoints[peer].str()}, {"shared_key", "reload-test-key"}, {"networks", {"10.91.0.0/24", "10.92.0.0/24"}}});
    return parse_config(value.dump());
}
Json route(Node& node, const Endpoint& endpoint, const std::string& network = "10.91.0.0/24") {
    const auto state = node.status();
    for (const auto& entry : state.at("routes")) if (entry.at("node") == endpoint.str() && entry.at("network") == network) return entry;
    return nullptr;
}
bool settled(Node& node) {
    const auto state = node.status();
    if (state.at("pending_connections") != 0) return false;
    for (const auto& peer : state.at("peers")) if (peer.at("state") != 3) return false;
    return true;
}
std::string session(Node& node, const Endpoint& remote) {
    const auto state = node.status();
    for (const auto& entry : state.at("end_sessions")) if (entry.at("node") == remote.str() && entry.at("network") == "10.91.0.0/24" && entry.at("ready") == true)
        return entry.at("id").get<std::string>();
    return {};
}
std::uint64_t counter(Node& node, const std::string& name) {
    const auto counters = node.status().at("counters"); return counters.count(name) ? counters.at(name).get<std::uint64_t>() : 0;
}
Bytes packet(unsigned source, unsigned destination, unsigned flow) {
    Bytes result(100); result[0] = 0x45; result[3] = 100; result[8] = 64; result[9] = 17;
    result[12] = 10; result[13] = 91; result[15] = source;
    result[16] = 10; result[17] = 91; result[19] = destination;
    result[20] = flow >> 8; result[21] = flow; result[22] = 0x12; result[23] = 0x34; result[25] = 80;
    return result;
}
void send(EventLoop& loop, const std::shared_ptr<Factory>& source, const std::shared_ptr<Factory>& destination, unsigned source_ip, unsigned destination_ip, unsigned flow) {
    const auto expected = destination->current()->delivered.size() + 1;
    CHECK(static_cast<bool>(source->current()->receive));
    source->current()->receive(packet(source_ip, destination_ip, flow));
    until(loop, [&] { return destination->current()->delivered.size() == expected; });
}
void peer_and_rebuild_tests() {
    EventLoop loop; const auto endpoints = ports(loop, 6);
    std::vector<Configure> configs{config(0, endpoints, {1,2}), config(1, endpoints, {0}), config(2, endpoints, {0}), config(3, endpoints, {0})};
    std::vector<std::shared_ptr<Factory>> factories;
    std::vector<std::unique_ptr<Node>> nodes;
    for (unsigned i = 0; i < 4; ++i) {
        std::shared_ptr<Factory> factory(new Factory); factories.push_back(factory);
        nodes.emplace_back(new Node(loop, configs[i], make_device(factory, configs[i]), options(factory)));
        if (i < 3) nodes.back()->start();
    }
    auto& a = *nodes[0]; const auto identity = a.public_key();
    diagnostics = [&] { for (const auto& node : nodes) std::cerr << node->status().dump(2) << '\n'; };
    until(loop, [&] { return settled(a) && settled(*nodes[1]) && settled(*nodes[2]); });
    send(loop, factories[0], factories[1], 1, 2, 101);
    send(loop, factories[0], factories[2], 1, 3, 102);
    const auto b_session = session(a, endpoints[1]), c_session = session(a, endpoints[2]);
    CHECK(!b_session.empty() && !c_session.empty());
    const auto initial_device = factories[0]->current(); const auto initial_down = counter(a, "peer_down");
    auto next = a.configuration(); std::reverse(next.peers.begin(), next.peers.end());
    auto result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "noop" && result.at("interrupted") == false);
    CHECK(a.public_key() == identity && factories[0]->calls == 1 && session(a, endpoints[2]) == c_session);
    next = a.configuration(); next.remote_desktop.enabled = true; next.remote_desktop.unattended = true;
    next.remote_desktop.networks.push_back(Network::parse("10.91.0.0/24")); next.remote_desktop.access = "all_tunnel_nodes";
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "remote" && result.at("interrupted") == false);
    CHECK(a.configuration().remote_desktop.access == "all_tunnel_nodes" && factories[0]->current() == initial_device);
    CHECK(counter(a, "peer_down") == initial_down && session(a, endpoints[1]) == b_session && session(a, endpoints[2]) == c_session);
    next = a.configuration(); PeerConfig added; added.address = endpoints[3]; added.shared_key = "reload-test-key"; added.networks = next.networks; next.peers.push_back(added);
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "peers" && result.at("changed_peers") == 1 && result.at("interrupted") == false);
    nodes[3]->start(); until(loop, [&] { return settled(a) && settled(*nodes[3]); });
    CHECK(session(a, endpoints[1]) == b_session && session(a, endpoints[2]) == c_session);
    // A first dial to the newly added D may fail before D starts, especially on
    // Windows; peer_down counts that attempt too. Existing session IDs above
    // prove that B/C were preserved without relying on this aggregate counter.
    CHECK(factories[0]->calls == 1);
    send(loop, factories[0], factories[3], 1, 4, 103); const auto d_session = session(a, endpoints[3]);
    next = a.configuration(); next.peers.erase(std::remove_if(next.peers.begin(), next.peers.end(), [&](const PeerConfig& peer) { return peer.address == endpoints[1]; }), next.peers.end());
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("interrupted") == true && route(a, endpoints[1]).is_null());
    CHECK(session(a, endpoints[1]).empty() && session(a, endpoints[2]) == c_session && session(a, endpoints[3]) == d_session);
    CHECK(!route(a, endpoints[2]).is_null() && !route(a, endpoints[3]).is_null()); nodes[1]->stop();
    next = a.configuration(); for (auto& peer : next.peers) if (peer.address == endpoints[2]) peer.shared_key = "rotated-reload-key";
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && route(a, endpoints[2]).is_null() && session(a, endpoints[2]).empty());
    CHECK(session(a, endpoints[3]) == d_session);
    auto remote = nodes[2]->configuration(); remote.peers[0].shared_key = "rotated-reload-key";
    CHECK(nodes[2]->apply_config(remote).at("mode") == "peers");
    until(loop, [&] { return settled(a) && settled(*nodes[2]); });
    send(loop, factories[0], factories[2], 1, 3, 104);
    CHECK(session(a, endpoints[2]) != c_session && session(a, endpoints[3]) == d_session && a.public_key() == identity);
    next = a.configuration(); for (auto& peer : next.peers) if (peer.address == endpoints[2]) peer.networks.resize(1);
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "peers");
    CHECK(route(a, endpoints[2], "10.92.0.0/24").is_null() && !route(a, endpoints[3], "10.92.0.0/24").is_null());
    until(loop, [&] { return settled(a) && settled(*nodes[2]); });
    CHECK(route(a, endpoints[2], "10.92.0.0/24").is_null() && session(a, endpoints[3]) == d_session);
    CHECK(factories[0]->calls == 1 && factories[0]->current() == initial_device);
    next = a.configuration(); next.networks.push_back(next.networks[0]);
    result = a.apply_config(next);
    CHECK(result.at("ok") == false && result.at("interrupted") == false && factories[0]->current() == initial_device);
    CHECK(session(a, endpoints[3]) == d_session);
    next = a.configuration(); next.tun_mtu = 1200;
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "rebuild" && result.at("interrupted") == true && result.at("running") == true);
    CHECK(initial_device->destroyed && !initial_device->receive && factories[0]->calls == 2 && factories[0]->live == 1 && factories[0]->peak == 1);
    CHECK(a.public_key() == identity && a.configuration().tun_mtu == 1200 && factories[0]->current()->config.tun_mtu == 1200);
    until(loop, [&] { return settled(a) && settled(*nodes[2]) && settled(*nodes[3]); });
    send(loop, factories[0], factories[3], 1, 4, 105);
    factories[0]->rejected_mtu = 1250; next = a.configuration(); next.tun_mtu = 1250;
    result = a.apply_config(next);
    CHECK(result.at("ok") == false && result.at("rolled_back") == true && result.at("running") == true);
    CHECK(a.configuration().tun_mtu == 1200 && a.public_key() == identity && factories[0]->live == 1 && factories[0]->peak == 1);
    factories[0]->rejected_mtu = 0;
    // A failed listener start happens after its new UDP socket is allocated.
    // Recovery must close that candidate socket before restoring the old one.
    {
        TcpListener conflict(loop, endpoints[5], [](evutil_socket_t fd) { evutil_closesocket(fd); });
        next = a.configuration(); next.listen.bind_address = endpoints[5];
        result = a.apply_config(next);
        CHECK(result.at("ok") == false && result.at("rolled_back") == true && result.at("running") == true);
        UdpTransport released(loop, endpoints[5], 1400, [](const Endpoint&, Bytes) {});
        CHECK(a.configuration().listen.bind_address == endpoints[0]);
    }
    factories[0]->bad_start_mtu = 1190; next = a.configuration(); next.tun_mtu = 1190;
    result = a.apply_config(next);
    CHECK(result.at("ok") == false && result.at("rolled_back") == true && result.at("running") == true);
    CHECK(a.public_key() == identity && factories[0]->peak == 1); factories[0]->bad_start_mtu = 0;
    factories[0]->reject_all = true; next = a.configuration(); next.tun_mtu = 1220;
    result = a.apply_config(next);
    CHECK(result.at("ok") == false && result.at("rolled_back") == false && result.at("running") == false && result.count("rollback_error"));
    CHECK(a.status().at("running") == false && factories[0]->live == 0 && a.configuration().tun_mtu == 1200 && a.public_key() == identity);
    { UdpTransport released(loop, endpoints[0], 1400, [](const Endpoint&, Bytes) {}); CHECK(true); }
    factories[0]->reject_all = false;
    result = a.apply_config(a.configuration());
    CHECK(result.at("ok") == true && result.at("mode") == "rebuild" && result.at("running") == true && a.public_key() == identity);
    next = a.configuration(); AdvertisedRoute exported; exported.tunnel = Network::parse("10.91.0.0/24"); exported.prefix = Network::parse("10.93.0.0/24"); exported.snat = true; next.advertise_routes.push_back(exported);
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "rebuild" && factories[0]->current()->exported.size() == 1);
    CHECK(a.status().at("local_exports")[0].at("active") == true);
    const auto old_copy = a.configuration();
    next = old_copy;
    auto update_ip = [](std::vector<NetworkConfig>& networks) { for (auto& network : networks) if (network.tunnel.str() == "10.91.0.0/24") network.tunnel_ip = IpAddress::parse("10.91.0.9"); };
    update_ip(next.networks); update_ip(next.listen.networks); for (auto& peer : next.peers) update_ip(peer.networks);
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "rebuild");
    CHECK(old_copy.networks[0].tunnel_ip.str() == "10.91.0.1" && a.configuration().networks[0].tunnel_ip.str() == "10.91.0.9");
    until(loop, [&] { return settled(a) && settled(*nodes[3]) && !route(*nodes[3], endpoints[0]).is_null() && route(*nodes[3], endpoints[0]).at("ip") == "10.91.0.9"; });
    send(loop, factories[0], factories[3], 9, 4, 106);
    for (auto& node : nodes) node->stop();
    next = a.configuration(); next.listen.address = next.listen.bind_address = endpoints[4];
    result = a.apply_config(next);
    CHECK(result.at("ok") == true && result.at("mode") == "rebuild" && result.at("running") == false && result.at("interrupted") == false);
    a.start(); CHECK(a.status().at("node") == endpoints[4].str() && a.public_key() == identity); a.stop();
    diagnostics = {}; nodes.clear(); for (const auto& factory : factories) CHECK(factory->live == 0 && factory->peak == 1);
}
void boundaries(const std::string& state_path) {
    EventLoop loop; const auto endpoints = ports(loop, 3);
    auto initial = config(0, endpoints, {});
    std::shared_ptr<Factory> factory(new Factory);
    NodeOptions plain; Node* active = nullptr; Json reentrant;
    plain.log = [&](const std::string& message) { if (active && message.find("started ") == 0) reentrant = active->apply_config(active->configuration()); };
    Node fixed(loop, initial, make_device(factory, initial), plain); active = &fixed; fixed.start();
    CHECK(reentrant.at("ok") == false && reentrant.at("error") == "reload_busy");
    auto next = initial; next.tun_mtu = 1200;
    auto result = fixed.apply_config(next);
    CHECK(result.at("ok") == false && result.at("error") == "device_factory_required" && result.at("running") == true && result.at("interrupted") == false);
    CHECK(fixed.configuration().tun_mtu == 1280 && factory->live == 1);
    fixed.stop(); active = nullptr;
    // Standalone allocation services can rebuild without a TUN factory.
    auto server_config = parse_config(Json{{"address_server", {{"address", endpoints[1].str()}, {"bind_address", endpoints[1].str()},
        {"state_file", state_path}, {"shared_key", "reload-service-key"}, {"networks", {"10.94.0.0/24"}}}}}.dump());
    {
        Node server(loop, server_config, nullptr); server.start(); const auto identity = server.public_key();
        next = server.configuration(); next.address_server.reclaim_after = 1000;
        result = server.apply_config(next);
        CHECK(result.at("ok") == true && result.at("mode") == "rebuild" && result.at("running") == true && result.at("interrupted") == true);
        CHECK(server.public_key() == identity && server.configuration().address_server.reclaim_after == 1000);
        CHECK(server.status().at("device") == "" && server.status().at("address_service").at("server").at("running") == true);
        server.stop();
    }
    std::remove(state_path.c_str()); std::remove((state_path + ".lock").c_str());
}
}
int main(int argc, char** argv) {
    try {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        SocketSystem sockets;
        const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        peer_and_rebuild_tests(); boundaries((argc > 1 ? std::string(argv[1]) : std::string("reload-test-state")) + "-" + suffix + ".json");
        std::cout << "Reload tests: " << checks << " checks passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
