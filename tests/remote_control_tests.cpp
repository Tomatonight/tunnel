#include "node.h"
#include "tcp_transport.h"
#include <csignal>
#include <iostream>
#include <stdexcept>

namespace {
using Json = wire::Json;
unsigned checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)

void rejected(const Json& value) {
    bool failed = false;
    try { parse_config(value.dump()); } catch (const config_error&) { failed = true; }
    CHECK(failed);
}
void config_tests() {
    const Json basic{{"address", "127.0.0.1:27001"}, {"networks", {"10.88.0.1/24"}}};
    auto value = basic;
    auto parsed = parse_config(value.dump());
    CHECK(!parsed.remote_desktop.enabled && !parsed.remote_desktop.configured);
    CHECK(!Json::parse(serialize_config(parsed)).count("remote_desktop"));
    value["remote_desktop"] = {{"enabled", true}};
    parsed = parse_config(value.dump());
    CHECK(parsed.remote_desktop.enabled && parsed.remote_desktop.configured);
    CHECK(parsed.remote_desktop.access == "authorized_devices" && !parsed.remote_desktop.unattended && parsed.remote_desktop.port == 47831);
    CHECK(parsed.remote_desktop.networks.size() == 1 && parsed.remote_desktop.networks[0].str() == "10.88.0.0/24");
    auto normalized = Json::parse(serialize_config(parsed));
    CHECK(normalized["remote_desktop"]["networks"] == Json({"10.88.0.0/24"}));
    value["remote_desktop"] = {{"enabled", true}, {"access", "all_tunnel_nodes"}, {"unattended", true},
        {"port", 47900}, {"device_name", "Desktop \xe6\xb5\x8b\xe8\xaf\x95"}};
    const auto text = serialize_config(parse_config(value.dump()));
    CHECK(serialize_config(parse_config(text)) == text);
    parsed = parse_config(text);
    CHECK(parsed.remote_desktop.unattended && parsed.remote_desktop.port == 47900);
    CHECK(parsed.remote_desktop.device_name == value["remote_desktop"]["device_name"]);
    value["networks"].push_back("fd00:88::1/64");
    rejected(value);
    value["remote_desktop"]["networks"] = {"10.88.0.0/24"};
    CHECK(parse_config(value.dump()).remote_desktop.networks.size() == 1);
    CHECK(Json::parse(serialize_config(parse_config(value.dump())))["remote_desktop"]["networks"].size() == 1);
    const auto valid = value;
    for (const auto& field : {"enabled", "unattended"}) { value = valid; value["remote_desktop"][field] = 1; rejected(value); }
    for (const auto& access : {"all", "anyone", "", "authorized_device"}) {
        value = valid; value["remote_desktop"]["access"] = access; rejected(value);
    }
    for (const Json& port : {Json(0), Json(-1), Json(65536), Json(1.5), Json("47831"), Json(true)}) {
        value = valid; value["remote_desktop"]["port"] = port; rejected(value);
    }
    for (const Json& networks : {Json::array(), Json({"10.89.0.0/24"}), Json({"10.88.0.1/24"}),
            Json({"10.88.0.0/24", "10.88.0.0/24"}), Json("10.88.0.0/24")}) {
        value = valid; value["remote_desktop"]["networks"] = networks; rejected(value);
    }
    for (const Json& name : {Json(1), Json(std::string(129, 'x')), Json("line\nfeed"), Json(std::string("a\0b", 3))}) {
        value = valid; value["remote_desktop"]["device_name"] = name; rejected(value);
    }
    value = valid; value["remote_desktop"]["unknown"] = true; rejected(value);
    value = valid; value["remote_desktop"] = true; rejected(value);
    value = valid; value["remote_desktop"]["enabled"] = false; value["remote_desktop"].erase("networks");
    CHECK(!parse_config(value.dump()).remote_desktop.enabled);
    CHECK(Json::parse(serialize_config(parse_config(value.dump())))["remote_desktop"]["networks"].empty());
    value = valid; value["remote_desktop"]["enabled"] = false; value["remote_desktop"]["networks"] = {"10.89.0.0/24"}; rejected(value);
    const Json legacy{{"listen", {{"enabled", true}, {"address", "127.0.0.1:27001"},
        {"networks", Json::array({{{"tunnel", "10.88.0.0/24"}, {"tunnel_ip", "10.88.0.1"}}})}}},
        {"peers", Json::array()}, {"remote_desktop", {{"enabled", true}, {"access", "all_tunnel_nodes"}}}};
    CHECK(parse_config(legacy.dump()).remote_desktop.enabled);
    CHECK(Json::parse(serialize_config(parse_config(legacy.dump())))["remote_desktop"]["access"] == "all_tunnel_nodes");
    const Json server{{"address_server", {{"address", "127.0.0.1:27002"}, {"shared_key", "service-key"}, {"networks", {"10.88.0.0/24"}}}},
        {"remote_desktop", {{"enabled", true}}}};
    rejected(server);
    value = server; value["remote_desktop"]["enabled"] = false;
    CHECK(!parse_config(serialize_config(parse_config(value.dump()))).remote_desktop.enabled);
    value = basic; value.erase("networks");
    value["address_clients"] = Json::array({{{"address", "127.0.0.1:27002"}, {"shared_key", "service-key"}, {"networks", {"10.88.0.0/24"}}}});
    value["remote_desktop"] = {{"enabled", true}};
    CHECK(parse_config(value.dump()).remote_desktop.networks[0].str() == "10.88.0.0/24");
    CHECK(serialize_config(parse_config(serialize_config(parse_config(value.dump())))) == serialize_config(parse_config(value.dump())));
}
class MemoryDevice : public PacketDevice {
public:
    void start(Receiver) override {}
    bool send(const Bytes&) override { return true; }
    std::string name() const override { return "remote-membership-test"; }
};
void until(EventLoop& loop, const std::function<bool()>& condition) {
    auto poll = loop.addTimer(std::chrono::milliseconds(10), [&](evutil_socket_t, short) { if (condition()) loop.breakLoop(); }, true);
    auto deadline = loop.addTimer(std::chrono::milliseconds(10000), [&](evutil_socket_t, short) { loop.breakLoop(); });
    loop.run(); CHECK(condition());
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
    if (result.size() != count) throw std::runtime_error("cannot reserve remote test ports");
    return result;
}
Configure config(unsigned i, const std::vector<Endpoint>& endpoints) {
    Json value{{"address", endpoints[i].str()}, {"networks", {"10.88.0." + std::to_string(i + 1) + "/24", "fd00:88::" + std::to_string(i + 1) + "/64"}},
        {"listen", {{"bind_address", endpoints[i].str()}}}, {"peers", Json::array()}};
    for (unsigned peer = 0; peer < 3; ++peer) if ((i == 1 || peer == 1) && i != peer)
        value["peers"].push_back({{"address", endpoints[peer].str()}, {"shared_key", "test-link"}, {"networks", {"10.88.0.0/24", "fd00:88::/64"}}});
    if (i == 2) value["remote_desktop"] = {{"enabled", true}, {"networks", {"10.88.0.0/24"}}, {"access", "all_tunnel_nodes"}, {"unattended", true}};
    return parse_config(value.dump());
}
Json rpc(Node& node, Json request) {
    if (!request.count("id")) request["id"] = 1;
    return node.remote_control(request.dump());
}
Json signed_proof(Node& node, const std::string& network = "10.88.0.0/24") {
    const auto reply = rpc(node, {{"method", "remote_sign"}, {"network", network}, {"payload", "0001020304aaff"}});
    CHECK(reply.at("ok") == true);
    auto proof = reply.at("result"); proof["method"] = "remote_verify"; proof["payload"] = "0001020304aaff"; return proof;
}
bool verify(Node& node, const Json& proof) {
    const auto reply = rpc(node, proof); CHECK(reply.at("ok") == true); return reply.at("result").at("valid").get<bool>();
}
bool reachable(Node& node, const Endpoint& remote) {
    const auto status = node.status();
    for (const auto& route : status.at("routes")) if (route.at("node") == remote.str()) return true;
    return false;
}
void runtime_tests() {
    EventLoop loop; const auto endpoints = ports(loop, 4);
    NodeOptions options; options.tick_ms = 10; options.heartbeat_ms = 100; options.failure_timeout_ms = 20000;
    options.reconnect_ms = 100; options.handshake_timeout_ms = 10000;
    std::vector<std::unique_ptr<Node>> nodes;
    for (unsigned i = 0; i < 3; ++i) nodes.emplace_back(new Node(loop, config(i, endpoints), std::unique_ptr<PacketDevice>(new MemoryDevice), options));
    CHECK(rpc(*nodes[0], {{"method", "remote_info"}}).at("result").at("networks").empty());
    CHECK(rpc(*nodes[0], {{"method", "remote_sign"}, {"network", "10.88.0.0/24"}, {"payload", "aa"}}).at("error") == "inactive_network");
    nodes[0]->start();
    auto early = signed_proof(*nodes[0]); CHECK(!verify(*nodes[2], early));
    nodes[1]->start(); nodes[2]->start();
    const auto converged = [&] {
        for (const auto& node : nodes) {
            const auto status = node->status();
            if (status.at("pending_connections") != 0) return false;
            for (const auto& peer : status.at("peers")) if (peer.at("state") != 3) return false;
        }
        return reachable(*nodes[0], endpoints[2]) && reachable(*nodes[2], endpoints[0]);
    };
    // A path may briefly exist on a nonpreferred simultaneous connection.
    // Complete connection arbitration before testing a stable membership.
    until(loop, converged);
    auto proof = signed_proof(*nodes[0]); CHECK(verify(*nodes[2], proof));
    auto info = rpc(*nodes[0], {{"method", "remote_info"}}).at("result");
    CHECK(info.at("networks").size() == 2 && info.at("remote_desktop").at("enabled") == false);
    CHECK(info.at("networks")[0].at("network") == "10.88.0.0/24" && info.at("networks")[0].at("tunnel_ip") == "10.88.0.1");
    CHECK(rpc(*nodes[2], {{"method", "remote_info"}}).at("result").at("remote_desktop").at("networks").size() == 1);
    CHECK(verify(*nodes[0], signed_proof(*nodes[2])));
    CHECK(verify(*nodes[2], signed_proof(*nodes[0], "fd00:88::/64")));
    for (const auto& field : {"source_ip", "node", "payload", "signature"}) {
        auto forged = proof;
        if (std::string(field) == "source_ip") forged[field] = "10.88.0.2";
        else if (std::string(field) == "node") forged[field] = endpoints[1].str();
        else if (std::string(field) == "payload") forged[field] = "ff01020304aaff";
        else forged[field] = std::string(128, '0');
        CHECK(!verify(*nodes[2], forged));
    }
    auto changed_network = proof; changed_network["network"] = "fd00:88::/64"; changed_network["source_ip"] = "fd00:88::1";
    CHECK(!verify(*nodes[2], changed_network));
    changed_network = proof; changed_network["network"] = "10.89.0.0/24"; changed_network["source_ip"] = "10.89.0.1";
    CHECK(!verify(*nodes[2], changed_network));
    auto unrelated = proof; unrelated["node"] = endpoints[3].str(); CHECK(!verify(*nodes[2], unrelated));
    auto local = proof; local["node"] = endpoints[2].str(); local["source_ip"] = "10.88.0.3"; CHECK(!verify(*nodes[2], local));
    Json request{{"method", "remote_sign"}, {"network", "10.88.0.0/24"}, {"payload", std::string(8192, 'a')}};
    CHECK(rpc(*nodes[0], request).at("ok") == true);
    request["payload"] = std::string(8194, 'a'); CHECK(rpc(*nodes[0], request).at("ok") == false);
    for (const auto& payload : {"", "AA", "a", "gg"}) { request["payload"] = payload; CHECK(rpc(*nodes[0], request).at("ok") == false); }
    request["payload"] = "aa"; request["network"] = "10.88.0.1/24"; CHECK(rpc(*nodes[0], request).at("ok") == false);
    request["network"] = "10.89.0.0/24"; CHECK(rpc(*nodes[0], request).at("error") == "inactive_network");
    const std::vector<std::string> invalid = {"[]", "{}", "{", "{\"id\":1,\"id\":2,\"method\":\"remote_info\"}",
        "{\"id\":1,\"method\":\"remote_info\",\"network\":\"10.88.0.0/24\"}",
        "{\"id\":1,\"method\":\"remote_verify\"}", "{\"id\":-1,\"method\":\"remote_info\"}",
        "{\"id\":9007199254740992,\"method\":\"remote_info\"}", "{\"id\":true,\"method\":\"remote_info\"}",
        "{\"id\":1.0,\"method\":\"remote_info\"}", "{\"id\":[],\"method\":\"remote_info\"}",
        "{\"id\":1,\"method\":\"remote_info\",\"x\":[[[[[[[[]]]]]]]]}", std::string(16385, 'x')};
    for (const auto& text : invalid) CHECK(nodes[0]->remote_control(text).at("ok") == false);
    CHECK(rpc(*nodes[0], {{"id", "desktop-request"}, {"method", "remote_info"}}).at("id") == "desktop-request");
    CHECK(rpc(*nodes[0], {{"method", "unknown"}}).at("error") == "unknown_method");
    CHECK(rpc(*nodes[0], {{"id", std::string(65, 'x')}, {"method", "remote_info"}}).at("ok") == false);
    auto malformed_signature = proof; malformed_signature["signature"] = "ab"; CHECK(rpc(*nodes[2], malformed_signature).at("ok") == false);
    const auto original_key = nodes[2]->public_key(); const auto previous_proof = signed_proof(*nodes[2]);
    nodes[2]->stop();
    CHECK(!verify(*nodes[2], proof));
    CHECK(rpc(*nodes[2], {{"method", "remote_info"}}).at("result").at("networks").empty());
    until(loop, [&] { return !reachable(*nodes[0], endpoints[2]); });
    CHECK(!verify(*nodes[0], previous_proof));
    nodes[2].reset(new Node(loop, config(2, endpoints), std::unique_ptr<PacketDevice>(new MemoryDevice), options));
    nodes[2]->start();
    until(loop, converged);
    CHECK(nodes[2]->public_key() != original_key);
    CHECK(!verify(*nodes[0], previous_proof));
    CHECK(verify(*nodes[0], signed_proof(*nodes[2])));
    nodes[1]->stop(); until(loop, [&] { return !reachable(*nodes[2], endpoints[0]); });
    CHECK(!verify(*nodes[2], proof));
    for (auto& node : nodes) node->stop();
    Json managed{{"address", endpoints[3].str()}, {"listen", {{"bind_address", endpoints[3].str()}}},
        {"address_clients", Json::array({{{"address", endpoints[0].str()}, {"shared_key", "allocator-key"}, {"networks", {"10.88.0.0/24"}}}})},
        {"remote_desktop", {{"enabled", true}}}};
    Node pending(loop, parse_config(managed.dump()), std::unique_ptr<PacketDevice>(new MemoryDevice), options); pending.start();
    CHECK(rpc(pending, {{"method", "remote_info"}}).at("result").at("networks").empty());
    CHECK(rpc(pending, {{"method", "remote_sign"}, {"network", "10.88.0.0/24"}, {"payload", "aa"}}).at("error") == "inactive_network");
    CHECK(!verify(pending, proof)); pending.stop();
}
}
int main() {
    try {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        SocketSystem sockets; config_tests(); runtime_tests();
        std::cout << "Remote control tests: " << checks << " checks passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
