#include "crypto.h"
#include "gossip.h"
#include "parse_config.h"
#include "peer.h"
#include "protocol.h"
#include "tunnel.h"
#include "udp_transport.h"
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {
unsigned checks = 0;
void check(bool value, const char* expression, unsigned line) {
    ++checks;
    if (!value) throw std::runtime_error(std::string("line ") + std::to_string(line) + ": " + expression);
}
#define CHECK(value) check(bool(value), #value, __LINE__)
using json = nlohmann::json;
void invalid_config(const json& value) {
    Configure result; std::string error;
    CHECK(!try_parse_config(value.dump(), &result, &error)); CHECK(!error.empty());
}
Endpoint node(unsigned n) { return Endpoint::parse("100.0.0." + std::to_string(n) + ":65535"); }
Network network() { return Network::parse("10.1.0.0/24"); }
void legacy_configuration_tests(const json& base) {
    auto config = parse_config(base.dump());
    CHECK(config.networks.size() == 2); CHECK(config.peers.size() == 1);
    CHECK(config.listen.bind_address.str() == "0.0.0.0:65535");
    CHECK(protocol::maximum_tun_mtu(1500, 4) == 1306);
    CHECK(protocol::maximum_tun_mtu(1500, 6) == 1286);
    auto d = base; d.erase("tun_mtu"); d.erase("transport_mtu"); d["listen"].erase("bind_address");
    CHECK(parse_config(d.dump()).tun_mtu == 1280);
    CHECK(parse_config(d.dump()).listen.bind_address.ip.unspecified());
    d = base; d["thread_num"] = 1; CHECK(parse_config(d.dump()).tun_mtu == 1280);
    d["thread_num"] = 2; invalid_config(d);
    d["thread_num"] = true; invalid_config(d);
    d = base; d["tun_mtu"] = 1306; CHECK(parse_config(d.dump()).tun_mtu == 1306);
    d["tun_mtu"] = 1307; invalid_config(d);
    d["tun_mtu"] = -1; invalid_config(d);
    d = base; d["transport_mtu"] = 1280; invalid_config(d);
    d = base; d["peers"][0]["networks"][0]["tunnel"] = "10.1.0.99/24";
    CHECK(parse_config(d.dump()).networks[0].tunnel.str() == "10.1.0.0/24");
    d["peers"][0]["networks"][0]["tunnel_ip"] = "10.1.0.3"; invalid_config(d);
    d = base; d["peers"][0]["networks"][1] = {{"tunnel", "10.0.0.0/8"}, {"tunnel_ip", "10.2.0.1"}}; invalid_config(d);
    d = base; d["listen"]["address"] = "0.0.0.0:65535"; invalid_config(d);
    d = base; d["listen"]["address"] = "100.0.0.1:65536"; invalid_config(d);
    d = base; d["peers"][0]["address"] = "100.0.0.1:65535"; invalid_config(d);
    d = base; d["peers"][0]["shared_key"] = ""; invalid_config(d);
    d = base; d["peers"].push_back(d["peers"][0]); invalid_config(d);
    d = base; d["peers"][0]["networks"][0]["tunnel_ip"] = "10.1.0.255"; invalid_config(d);
    d = base; d["peers"][0]["networks"][0]["tunnel_ip"] = "10.2.0.1"; invalid_config(d);
    d = base; d["auto_key"] = true; invalid_config(d);
    d = base; d["listen"]["enabled"] = false; CHECK(!parse_config(d.dump()).listen.enabled);
    d = base; d["listen"]["address"] = "[2001:db8::1]:65535";
    d["listen"].erase("bind_address"); d["peers"][0]["address"] = "[2001:db8::2]:65535";
    CHECK(parse_config(d.dump()).listen.bind_address.str() == "[::]:65535");
    d["peers"][0]["networks"][1] = {{"tunnel", "fd00::/64"}, {"tunnel_ip", "fd00::1"}};
    CHECK(parse_config(d.dump()).networks.size() == 2);
    d["tun_mtu"] = 1200; invalid_config(d);
    std::string error;
    CHECK(!try_parse_config("{\"listen\":{},\"listen\":{}}", &config, &error));
    CHECK(error.find("duplicate") != std::string::npos);
    CHECK(!try_parse_config("[]", &config, &error));
    CHECK(!try_parse_config("{\"shared_key\": SECRET_SHOULD_NOT_APPEAR}", &config, &error));
    CHECK(error.find("SECRET_SHOULD_NOT_APPEAR") == std::string::npos);
    CHECK(!try_parse_config(base.dump(), nullptr, &error));
    CHECK(!try_parse_config(std::string(1048577, ' '), &config, &error));
    CHECK(error.find("1 MiB") != std::string::npos);
    CHECK(!try_parse_config(std::string(40, '[') + "0" + std::string(40, ']'), &config, &error));
    CHECK(error.find("nesting") != std::string::npos);
    d = base; d["peers"] = json::array();
    for (unsigned i = 0; i < 257; ++i) d["peers"].push_back(base["peers"][0]);
    invalid_config(d);
    d = base; d["peers"][0]["networks"] = json::array();
    for (unsigned i = 0; i < 64; ++i) d["peers"][0]["networks"].push_back(
        {{"tunnel", "172.20." + std::to_string(i) + ".0/24"}, {"tunnel_ip", "172.20." + std::to_string(i) + ".1"}});
    invalid_config(d); // Limit applies to the union, including listen.networks.
    CHECK(Network::parse("2001:db8:0:0::1/64") == Network::parse("2001:db8::/64"));
    CHECK(Endpoint::parse("[2001:0db8::1]:1234") == Endpoint::parse("[2001:db8::1]:1234"));
}

json network_policy(const std::vector<NetworkConfig>& networks) {
    auto result = json::object();
    for (const auto& n : networks) result[n.tunnel.str()] = n.tunnel_ip.str();
    return result;
}
json expanded_config(const Configure& c) {
    json result = {{"tun_mtu", c.tun_mtu}, {"transport_mtu", c.transport_mtu}, {"device_backend", c.device_backend},
        {"address", c.listen.address.str()}, {"bind", c.listen.bind_address.str()},
        {"enabled", c.listen.enabled}, {"networks", network_policy(c.networks)},
        {"inbound_networks", network_policy(c.listen.networks)}, {"peers", json::object()}};
    for (const auto& peer : c.peers) result["peers"][peer.address.str()] = {
        {"key", peer.shared_key}, {"networks", network_policy(peer.networks)}, {"transport", peer.transport}};
    return result;
}
void roundtrip_policy(const json& source) {
    const auto original = parse_config(source.dump());
    const auto normalized = serialize_config(original);
    const auto reloaded = parse_config(normalized);
    CHECK(expanded_config(original) == expanded_config(reloaded));
    CHECK(serialize_config(reloaded) == normalized);
}
void configuration_tests(const json& base) {
    const auto legacy = json::parse(R"({
      "tun_mtu":1280,"transport_mtu":1500,
      "listen":{"enabled":true,"address":"100.0.0.1:65535","bind_address":"0.0.0.0:65535",
        "networks":[{"tunnel":"10.1.0.0/24","tunnel_ip":"10.1.0.2"}]},
      "peers":[{"address":"100.0.0.2:65535","shared_key":"use-a-random-high-entropy-secret",
        "networks":[{"tunnel":"10.1.0.0/24","tunnel_ip":"10.1.0.2"},
                    {"tunnel":"192.168.0.0/24","tunnel_ip":"192.168.0.2"}]}]
    })");
    legacy_configuration_tests(legacy);
    const auto simple = parse_config(base.dump());
    CHECK(simple.networks.size() == 1 && simple.peers.size() == 1);
    CHECK(simple.networks[0].tunnel.str() == "10.1.0.0/24");
    CHECK(simple.networks[0].tunnel_ip.str() == "10.1.0.2");
    CHECK(simple.listen.enabled && simple.listen.bind_address.str() == "0.0.0.0:65535");
    CHECK(simple.tun_mtu == 1280 && simple.transport_mtu == 1500);
    auto old_single = legacy; old_single["peers"][0]["networks"].erase(1);
    CHECK(expanded_config(simple) == expanded_config(parse_config(old_single.dump())));
    CHECK(serialize_config(simple) == serialize_config(parse_config(old_single.dump())));
    roundtrip_policy(base); roundtrip_policy(legacy);
    auto canonical = json::parse(serialize_config(parse_config(legacy.dump())));
    CHECK(canonical.at("networks") == json({"10.1.0.2/24", "192.168.0.2/24"}));
    CHECK(canonical.at("listen").at("networks") == json({"10.1.0.0/24"}));
    CHECK(canonical.at("peers")[0].at("networks") == json({"10.1.0.0/24", "192.168.0.0/24"}));
    CHECK(!canonical.contains("tun_mtu") && !canonical.contains("transport_mtu"));
#if defined(__linux__) && !defined(__ANDROID__)
    CHECK(simple.device_backend == "kernel");
#else
    CHECK(simple.device_backend == "tun");
#endif
    CHECK(Configure().device_backend == simple.device_backend);
    CHECK(canonical.at("device_backend") == simple.device_backend);
    for (auto source : {base, legacy}) {
        source["device_backend"] = "kernel";
        CHECK(parse_config(source.dump()).device_backend == "kernel");
        CHECK(json::parse(serialize_config(parse_config(source.dump())))["device_backend"] == "kernel");
        roundtrip_policy(source);
        source["device_backend"] = "tun";
        CHECK(parse_config(source.dump()).device_backend == "tun");
        CHECK(json::parse(serialize_config(parse_config(source.dump())))["device_backend"] == "tun");
        roundtrip_policy(source);
        for (const auto& invalid_backend : json::array({"auto", "Kernel", "", true, 1, nullptr, json::array(), json::object()})) {
            source["device_backend"] = invalid_backend;
            invalid_config(source);
        }
    }
    auto invalid_backend_config = simple; invalid_backend_config.device_backend = "unknown";
    bool backend_rejected = false;
    try { serialize_config(invalid_backend_config); } catch (const config_error&) { backend_rejected = true; }
    CHECK(backend_rejected);
    // Defaults remain compatible with existing UDP configurations. Transport is
    // a per-adjacency choice and survives legacy-to-simplified normalization.
    CHECK(simple.peers[0].transport == "udp");
    CHECK(parse_config(legacy.dump()).peers[0].transport == "udp");
    CHECK(!canonical["peers"][0].contains("transport"));
    for (auto source : {base, legacy}) {
        source["peers"][0]["transport"] = "tcp";
        CHECK(parse_config(source.dump()).peers[0].transport == "tcp");
        CHECK(json::parse(serialize_config(parse_config(source.dump())))["peers"][0]["transport"] == "tcp");
        roundtrip_policy(source);
        source["peers"][0]["transport"] = "udp";
        CHECK(parse_config(source.dump()).peers[0].transport == "udp");
        CHECK(!json::parse(serialize_config(parse_config(source.dump())))["peers"][0].contains("transport"));
        for (const auto& invalid_transport : json::array({"auto", "TCP", "", true, 1, nullptr, json::array(), json::object()})) {
            source["peers"][0]["transport"] = invalid_transport;
            invalid_config(source);
        }
    }
    auto mixed = base;
    mixed["peers"][0]["transport"] = "tcp";
    auto second = mixed["peers"][0]; second["address"] = "100.0.0.3:65535"; second.erase("transport");
    mixed["peers"].push_back(second);
    const auto mixed_config = parse_config(mixed.dump());
    CHECK(mixed_config.peers[0].transport == "tcp" && mixed_config.peers[1].transport == "udp");
    roundtrip_policy(mixed);
    // TCP links may coexist with UDP transit links, so they retain the same MTU
    // validation instead of allowing oversized packets on only some paths.
    auto tcp_oversized = base; tcp_oversized["peers"][0]["transport"] = "tcp";
    tcp_oversized["tun_mtu"] = 1307; invalid_config(tcp_oversized);
    auto d = base; d.erase("peers");
    CHECK(parse_config(d.dump()).peers.empty()); roundtrip_policy(d);
    d["listen"] = json::object(); CHECK(parse_config(d.dump()).listen.enabled);
    d = base; d["thread_num"] = 1; CHECK(parse_config(d.dump()).tun_mtu == 1280);
    CHECK(!json::parse(serialize_config(parse_config(d.dump()))).contains("thread_num"));
    d["thread_num"] = 2; invalid_config(d);
    d = base; d["tun_mtu"] = 1306; roundtrip_policy(d);
    d["tun_mtu"] = 1307; invalid_config(d);
    d = base; d["transport_mtu"] = 1600; d["tun_mtu"] = 1400; roundtrip_policy(d);
    d = base; d.erase("address"); invalid_config(d);
    d = base; d.erase("networks"); invalid_config(d);
    d = base; d["networks"] = json::array(); invalid_config(d);
    d = base; d["networks"] = nullptr; invalid_config(d);
    d = base; d["networks"] = {"10.1.0.2"}; invalid_config(d);
    d = base; d["networks"] = {"10.1.0.0/24"}; invalid_config(d);
    d = base; d["networks"] = {"10.1.0.255/24"}; invalid_config(d);
    d = base; d["networks"].push_back("10.1.0.3/24"); invalid_config(d);
    d = base; d["networks"].push_back("10.2.0.1/8"); invalid_config(d);
    d = base; d["address"] = "0.0.0.0:65535"; invalid_config(d);
    d = base; d["address"] = "100.0.0.1:65536"; invalid_config(d);
    d = base; d["listen"] = {{"address", "100.0.0.1:65535"}}; invalid_config(d);
    d = legacy; d["address"] = "100.0.0.1:65535"; invalid_config(d);
    d = base; d["networks"] = legacy["listen"]["networks"]; invalid_config(d);
    d = base; d["peers"][0]["networks"] = legacy["listen"]["networks"]; invalid_config(d);
    d = base; d["listen"] = {{"networks", legacy["listen"]["networks"]}}; invalid_config(d);
    d = base; d["listen"] = {{"enabled", "true"}}; invalid_config(d);
    d = base; d["listen"] = {{"bind_address", "[::]:65535"}}; invalid_config(d);
    d = base; d["peers"] = nullptr; invalid_config(d);
    d = base; d["peers"][0]["shared_key"] = ""; invalid_config(d);
    d = base; d["peers"][0]["address"] = base["address"]; invalid_config(d);
    d = base; d["peers"][0]["networks"] = json::array(); invalid_config(d);
    d = base; d["peers"][0]["networks"] = {"10.2.0.0/24"}; invalid_config(d);
    d = base; d["peers"][0]["networks"] = {"10.0.0.0/8"}; invalid_config(d);
    d = base; d["peers"][0]["networks"] = {"10.1.0.2/24"}; invalid_config(d);
    d = base; d["peers"][0]["networks"] = {"10.1.0.0/24", "10.1.0.0/24"}; invalid_config(d);
    d = base; d["listen"] = {{"networks", {"10.2.0.0/24"}}}; invalid_config(d);
    d = base; d["listen"] = {{"enabled", false}, {"networks", json::array()}, {"bind_address", "127.0.0.1:45000"}};
    roundtrip_policy(d);
    canonical = json::parse(serialize_config(parse_config(d.dump())));
    CHECK(canonical["listen"]["enabled"] == false && canonical["listen"]["networks"].empty());
    CHECK(canonical["listen"]["bind_address"] == "127.0.0.1:45000");
    d = old_single; d["listen"]["networks"] = json::array(); roundtrip_policy(d);
    canonical = json::parse(serialize_config(parse_config(d.dump())));
    CHECK(canonical["listen"]["networks"].empty());

    // A formerly implicit single-network peer must fail closed when a second
    // local network is added, rather than silently receiving both permissions.
    d = base; d["networks"].push_back("192.168.0.2/24"); invalid_config(d);
    d["peers"][0]["networks"] = {"10.1.0.0/24"}; roundtrip_policy(d);
    CHECK(parse_config(d.dump()).peers[0].networks.size() == 1);
    canonical = json::parse(serialize_config(parse_config(d.dump())));
    CHECK(canonical["peers"][0]["networks"] == json({"10.1.0.0/24"}));
    canonical["networks"].push_back("172.18.0.2/24");
    CHECK(parse_config(canonical.dump()).peers[0].networks.size() == 1);
    CHECK(parse_config(canonical.dump()).peers[0].networks[0].tunnel == network());
    d["peers"].push_back({{"address", "100.0.0.3:65535"}, {"shared_key", "different-peer-key"}, {"networks", {"192.168.0.0/24"}}});
    d["listen"] = {{"networks", {"192.168.0.0/24"}}}; roundtrip_policy(d);

    d = base; d["address"] = "[2001:db8::1]:65535"; d["peers"][0]["address"] = "[2001:db8::2]:65535";
    d["networks"] = {"fd00:0:0::123/64"};
    CHECK(parse_config(d.dump()).listen.bind_address.str() == "[::]:65535");
    CHECK(parse_config(d.dump()).networks[0].tunnel_ip.str() == "fd00::123"); roundtrip_policy(d);
    d["peers"][0]["networks"] = {"fd00:0::/64"}; roundtrip_policy(d);
    d["peers"][0]["networks"].push_back("fd00::/64"); invalid_config(d);
    d["peers"][0].erase("networks"); d["tun_mtu"] = 1200; invalid_config(d);
    d = base; d["peers"] = json::array(); d["networks"] = json::array();
    for (unsigned i = 0; i < 64; ++i) d["networks"].push_back("172.20." + std::to_string(i) + ".1/24");
    CHECK(parse_config(d.dump()).networks.size() == 64); roundtrip_policy(d);
    d["networks"].push_back("172.20.64.1/24"); invalid_config(d);
    // Caller-built configuration objects must not serialize a permission using
    // an undeclared network or a different local host address.
    auto invalid = simple; invalid.peers[0].networks[0].tunnel_ip = IpAddress::parse("10.1.0.3");
    bool rejected = false;
    try { serialize_config(invalid); } catch (const config_error&) { rejected = true; }
    CHECK(rejected);
    invalid = simple; invalid.peers[0].transport = "quic"; rejected = false;
    try { serialize_config(invalid); } catch (const config_error&) { rejected = true; }
    CHECK(rejected);
}

void crypto_tests() {
    IdentityKey identity, other;
    const Bytes message{1,2,3,4}; auto signature = identity.sign(message);
    CHECK(IdentityKey::verify(identity.public_key(), message, signature));
    CHECK(!IdentityKey::verify(other.public_key(), message, signature));
    signature[0] ^= 1; CHECK(!IdentityKey::verify(identity.public_key(), message, signature));
    CHECK(identity.public_key() == identity.public_key());
    Secret secret{}; secret.fill(0x73); const auto id = random_session_id();
    auto left = derive_keys(secret, id, CryptoScope::Link, "A/B", true);
    auto right = derive_keys(secret, id, CryptoScope::Link, "A/B", false);
    CHECK(left.send == right.receive); CHECK(left.receive == right.send); CHECK(left.send != left.receive);
    CHECK(derive_keys(secret, id, CryptoScope::EndToEnd, "A/B", true).send != left.send);
    CHECK(derive_keys(secret, random_session_id(), CryptoScope::Link, "A/B", true).send != left.send);
    CryptoSession a(id, left, CryptoScope::Link), b(id, right, CryptoScope::Link);
    const Bytes aad{8,9}; auto packet = a.seal(message, aad); Bytes decoded;
    CHECK(packet.size() == message.size() + protocol::record_overhead);
    auto corrupt = packet; corrupt.back() ^= 1;
    CHECK(!b.open(corrupt, decoded, aad)); CHECK(decoded.empty());
    corrupt = packet; corrupt[31] = 60;
    CHECK(!b.open(corrupt, decoded, aad));
    CHECK(!b.open(packet, decoded, Bytes{8,10}));
    CHECK(b.open(packet, decoded, aad)); CHECK(decoded == message);
    CHECK(!b.open(packet, decoded, aad)); CHECK(decoded.empty());
    CHECK(a.open(b.seal(message), decoded)); CHECK(decoded == message);
    auto first = a.seal(message), second = a.seal(message);
    CHECK(b.open(second, decoded)); CHECK(b.open(first, decoded)); CHECK(!b.open(first, decoded));
    auto old = a.seal(message);
    for (unsigned i = 0; i < 65; ++i) CHECK(b.open(a.seal(message), decoded));
    CHECK(!b.open(old, decoded));
    CHECK(b.open(a.seal({}), decoded)); CHECK(decoded.empty());
    auto intact = a.seal(message);
    for (std::size_t length = 0; length < intact.size(); ++length)
        CHECK(!b.open(Bytes(intact.begin(), intact.begin() + length), decoded));
    CHECK(b.open(intact, decoded));
    CryptoSession different(random_session_id(), right, CryptoScope::Link);
    CHECK(!different.open(a.seal(message), decoded));
}

protocol::ForwardHeader header() {
    protocol::ForwardHeader h; h.network = network(); h.source = node(1); h.destination = node(4); h.flow_id = 1234; return h;
}
void protocol_tests() {
    auto h = header(); Bytes packet(1280, 0x42), decoded;
    auto encoded = protocol::encode(h, packet);
    CHECK(encoded.size() == 1280 + protocol::forwarding_header_size);
    protocol::ForwardHeader parsed;
    CHECK(protocol::decode(encoded, &parsed, &decoded)); CHECK(decoded == packet);
    CHECK(parsed.source == h.source && parsed.destination == h.destination && parsed.flow_id == h.flow_id);
    auto aad = protocol::end_to_end_aad(h); --h.hop_limit;
    CHECK(protocol::end_to_end_aad(h) == aad);
    ++h.flow_id; CHECK(protocol::end_to_end_aad(h) != aad);
    encoded[2] = 0; CHECK(!protocol::decode(encoded, &parsed, &decoded));
    encoded = protocol::encode(header(), packet); encoded.push_back(0); CHECK(!protocol::decode(encoded, &parsed, &decoded));
    encoded = protocol::encode(header(), packet); encoded[4] = 9; CHECK(!protocol::decode(encoded, &parsed, &decoded));
    encoded = protocol::encode(header(), packet); encoded[21] = 33; CHECK(!protocol::decode(encoded, &parsed, &decoded));
    h = header(); h.kind = protocol::PacketKind::Multicast; h.destination = Endpoint();
    CHECK(protocol::decode(protocol::encode(h, packet), &parsed, &decoded));
}

PathAnnouncement route(const std::vector<Endpoint>& path, unsigned key_value = 1) {
    PathAnnouncement result; result.network = network(); result.destination = node(4);
    result.tunnel_ip = IpAddress::parse("10.1.0.4"); result.public_key.fill(static_cast<unsigned char>(key_value)); result.path = path; return result;
}
void routing_tests() {
    const auto a = node(1), b = node(2), c = node(3), d = node(4), e = node(5);
    NetworkConfig local; local.tunnel = network(); local.tunnel_ip = IpAddress::parse("10.1.0.1");
    Gossip table(a, {local}); table.authorize(b, {network()}); table.authorize(c, {network()});
    CHECK(!table.announce(b, route({b,d})));
    table.set_available(b, true); table.set_available(c, true);
    CHECK(table.announce(b, route({b,d})));
    CHECK(table.announce(c, route({c,d}, 2)));
    CHECK(table.next_hops(network(), d).size() == 2);
    CHECK(table.accept_rpf(network(), d, b)); CHECK(!table.accept_rpf(network(), d, c));
    PublicKey key{}; CHECK(table.public_key(d, &key)); CHECK(key[0] == 2);
    Endpoint selected, again; std::set<Endpoint> selected_peers;
    for (unsigned i = 0; i < 20; ++i) {
        CHECK(table.select_unicast(network(), d, i, &selected)); CHECK(table.select_unicast(network(), d, i, &again));
        CHECK(selected == again); selected_peers.insert(selected);
    }
    CHECK(selected_peers.size() == 2);
    CHECK(!table.announce(b, route({b,a,d})));
    CHECK(!table.announce(b, route({b,c,b,d})));
    CHECK(!table.announce(b, route({c,d})));
    auto wrong = route({b,d}); wrong.network = Network::parse("192.168.0.0/24");
    CHECK(!table.announce(b, wrong));
    wrong = route({b,d}); wrong.tunnel_ip = local.tunnel_ip; CHECK(!table.announce(b, wrong));
    table.withdraw(c, network(), d); CHECK(table.public_key(d, &key)); CHECK(key[0] == 1);
    CHECK(table.announce(c, route({c,e,d}, 3)));
    CHECK(table.next_hops(network(), d) == std::vector<Endpoint>{b});
    // Losing adjacency A-B must not remove C's path merely because it contains B.
    CHECK(table.announce(c, route({c,b,d}, 4)));
    table.set_available(b, false);
    CHECK(table.next_hops(network(), d) == std::vector<Endpoint>{c});
    CHECK(table.public_key(d, &key) && key[0] == 4);
    CHECK(table.node_for_ip(network(), IpAddress::parse("10.1.0.4"), &selected) && selected == d);
    table.set_available(c, false); CHECK(table.size() == 0); CHECK(!table.public_key(d, &key));
}

void peer_tests(const Configure& config) {
    Peer peer(config.peers.front()); const Peer::Time now{};
    auto generation = peer.begin_connection(); CHECK(peer.state() == PEER_STATE_CONNECTING);
    CHECK(peer.tcp_authenticated(generation, now)); CHECK(peer.state() == PEER_STATE_VERIFICATING);
    peer.sent_udp_probe(42); CHECK(!peer.authenticated_udp_ack(generation, 43, now));
    CHECK(peer.authenticated_udp_ack(generation, 42, now)); CHECK(peer.state() == PEER_STATE_ESTABLISHED);
    CHECK(!peer.authenticated_udp_ack(generation, 42, now));
    CHECK(peer.allows(network())); CHECK(!peer.allows(Network::parse("172.16.0.0/16")));
    CHECK(!peer.expired(now + std::chrono::seconds(1), std::chrono::seconds(5)));
    CHECK(peer.expired(now + std::chrono::seconds(6), std::chrono::seconds(5)));
    peer.disconnect(); const auto next = peer.begin_connection(); CHECK(next != generation);
    CHECK(!peer.tcp_authenticated(generation, now)); CHECK(peer.tcp_authenticated(next, now));
    peer.sent_udp_probe(42); CHECK(!peer.authenticated_udp_ack(generation, 42, now));
    peer.authenticated_tcp_activity(next, now + std::chrono::seconds(10));
    CHECK(peer.expired(now + std::chrono::seconds(10), std::chrono::seconds(5)));
}

Bytes ipv4_packet(std::size_t size) {
    Bytes packet(size); packet[0] = 0x45;
    packet[2] = static_cast<unsigned char>(size >> 8); packet[3] = static_cast<unsigned char>(size);
    packet[8] = 64; packet[9] = 17;
    packet[12] = 10; packet[13] = 1; packet[15] = 2;
    packet[16] = 10; packet[17] = 1; packet[19] = 4;
    packet[20] = 0x12; packet[21] = 0x34; packet[22] = 0x56; packet[23] = 0x78;
    return packet;
}
void tunnel_tests(const Configure& config) {
    Tunnel tunnel(config.networks.front(), config.tun_mtu); PacketInfo info;
    auto packet = ipv4_packet(1280);
    CHECK(tunnel.inspect(packet, &info, true)); CHECK(info.kind == protocol::PacketKind::Unicast);
    const auto flow = info.flow_id; packet[100] = 1;
    CHECK(tunnel.inspect(packet, &info, true)); CHECK(flow == info.flow_id);
    packet[20] ^= 1; CHECK(tunnel.inspect(packet, &info, true)); CHECK(flow != info.flow_id);
    CHECK(!tunnel.inspect(ipv4_packet(1281), &info, true));
    packet = ipv4_packet(100); packet[15] = 3; CHECK(!tunnel.inspect(packet, &info, true)); CHECK(tunnel.inspect(packet, &info, false));
    packet = ipv4_packet(100); packet[19] = 255;
    CHECK(tunnel.inspect(packet, &info, true)); CHECK(info.kind == protocol::PacketKind::Broadcast);
    packet[16] = 239; CHECK(tunnel.inspect(packet, &info, true)); CHECK(info.kind == protocol::PacketKind::Multicast);
    packet = ipv4_packet(100); packet[6] = 0x20;
    CHECK(tunnel.inspect(packet, &info, true)); const auto fragment_flow = info.flow_id;
    packet[6] = 0; packet[7] = 1; packet[20] = 0;
    CHECK(tunnel.inspect(packet, &info, true)); CHECK(fragment_flow == info.flow_id);
    packet = ipv4_packet(100); packet[3] = 101; CHECK(!tunnel.inspect(packet, &info, true));
}

void event_tests() {
    EventLoop loop; bool called = false;
    auto timer = loop.addTimer(std::chrono::milliseconds(1), [&](evutil_socket_t, short) { called = true; loop.breakLoop(); });
    CHECK(timer); CHECK(loop.run() == 0); CHECK(called);
    EventLoop bad;
    auto throwing = bad.addTimer(std::chrono::milliseconds(1), [](evutil_socket_t, short) { throw std::runtime_error("callback failure"); });
    CHECK(throwing); bool reported = false;
    try { bad.run(); } catch (const std::runtime_error& e) { reported = std::string(e.what()) == "callback failure"; }
    CHECK(reported);
    EventLoop self_throw; EventLoop::Handle self_releasing;
    self_releasing = self_throw.addTimer(std::chrono::milliseconds(1), [&](evutil_socket_t, short) {
        self_releasing.reset(); throw std::runtime_error("released callback");
    });
    reported = false;
    try { self_throw.run(); } catch (const std::runtime_error& e) { reported = std::string(e.what()) == "released callback"; }
    CHECK(reported);
    EventLoop lifecycle; bool canceled_called = false, released_called = false;
    auto canceled = lifecycle.addTimer(std::chrono::milliseconds(1), [&](evutil_socket_t, short) { canceled_called = true; });
    canceled.reset();
    EventLoop::Handle released;
    released = lifecycle.addTimer(std::chrono::milliseconds(5), [&](evutil_socket_t, short) {
        released.reset(); released_called = true; lifecycle.breakLoop();
    });
    CHECK(lifecycle.run() == 0); CHECK(!canceled_called && released_called);
    EventLoop::Handle survivor;
    { EventLoop temporary; survivor = temporary.addTimer(std::chrono::seconds(1), [](evutil_socket_t, short) {}); }
    CHECK(!survivor->valid()); CHECK(survivor->add() == -1);
}

void udp_tests(unsigned family) {
    EventLoop loop; bool received = false, timeout = false;
    Endpoint bind; bind.ip = IpAddress::parse(family == 4 ? "127.0.0.1" : "::1");
    const auto max_payload = 1500 - protocol::outer_overhead(family);
    Secret secret{}; secret.fill(0x42); const auto id = random_session_id();
    CryptoSession left(id, derive_keys(secret, id, CryptoScope::Link, "test", true), CryptoScope::Link);
    CryptoSession right(id, derive_keys(secret, id, CryptoScope::Link, "test", false), CryptoScope::Link);
    const auto end_id = random_session_id();
    CryptoSession origin(end_id, derive_keys(secret, end_id, CryptoScope::EndToEnd, "net/A/B", true), CryptoScope::EndToEnd);
    CryptoSession destination(end_id, derive_keys(secret, end_id, CryptoScope::EndToEnd, "net/A/B", false), CryptoScope::EndToEnd);
    const auto original = ipv4_packet(1280); auto h = header();
    const auto wire = left.seal(protocol::encode(h, origin.seal(original, protocol::end_to_end_aad(h))));
    CHECK(wire.size() == original.size() + protocol::unicast_overhead);
    CHECK(wire.size() + protocol::outer_overhead(family) <= 1500);
    UdpTransport a(loop, bind, max_payload, [](const Endpoint&, Bytes) {});
    UdpTransport b(loop, bind, max_payload, [&](const Endpoint& remote, Bytes packet) {
        CHECK(remote == a.local_address()); Bytes forwarded, encrypted, plain; protocol::ForwardHeader parsed;
        CHECK(right.open(packet, forwarded)); CHECK(protocol::decode(forwarded, &parsed, &encrypted));
        CHECK(destination.open(encrypted, plain, protocol::end_to_end_aad(parsed))); CHECK(plain == original);
        received = true; loop.breakLoop();
    });
    auto deadline = loop.addTimer(std::chrono::seconds(2), [&](evutil_socket_t, short) { timeout = true; loop.breakLoop(); });
    CHECK(deadline); CHECK(!a.send(b.local_address(), Bytes(max_payload + 1))); CHECK(a.counters().oversize == 1);
    CHECK(a.send(b.local_address(), wire)); CHECK(loop.run() == 0); CHECK(received && !timeout);
    CHECK(a.counters().sent == 1); CHECK(b.counters().received == 1);
    bool protect_called = false, refused = false;
    try { UdpTransport failed(loop, bind, max_payload, [](const Endpoint&, Bytes) {}, [&](evutil_socket_t) { protect_called = true; return false; }); }
    catch (const std::runtime_error&) { refused = true; }
    CHECK(protect_called && refused);
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("expected sample configuration path");
        SocketSystem sockets;
        std::ifstream file(argv[1]); if (!file) throw std::runtime_error("cannot read test configuration");
        json base; file >> base;
        configuration_tests(base); crypto_tests(); protocol_tests(); routing_tests();
        peer_tests(parse_config(base.dump())); tunnel_tests(parse_config(base.dump())); event_tests(); udp_tests(4); udp_tests(6);
        std::cout << "Passed " << checks << " checks (configuration, AEAD/replay, routing, lifecycle, MTU, event loop, UDP)\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "FAILED: " << e.what() << '\n'; return 1; }
}
