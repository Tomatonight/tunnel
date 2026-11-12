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
NodeId node_id(unsigned n) { return IpAddress::parse("10.1.0." + std::to_string(n)); }
Network network() { return Network::parse("10.1.0.0/24"); }
json network_policy(const std::vector<NetworkConfig>& networks) {
    auto result = json::object();
    for (const auto& n : networks) result[n.tunnel.str()] = n.tunnel_ip.str();
    return result;
}
json expanded_config(const Configure& c) {
    json result = {{"tun_mtu", c.tun_mtu}, {"transport_mtu", c.transport_mtu}, {"device_backend", c.device_backend},
        {"bind", c.listen.bind_address.str()}, {"enabled", c.listen.enabled}, {"listen_key", c.listen.shared_key}, {"networks", network_policy(c.networks)},
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
    const auto simple = parse_config(base.dump());
    CHECK(simple.networks.size() == 1 && simple.peers.size() == 1);
    CHECK(simple.networks[0].tunnel.str() == "10.1.0.0/24");
    CHECK(simple.networks[0].tunnel_ip.str() == "10.1.0.2");
    CHECK(simple.listen.enabled && simple.listen.bind_address.str() == "100.0.0.1:65535");
    CHECK(simple.listen.shared_key.empty());
    CHECK(simple.peers[0].transport == "tcp");
    CHECK(simple.tun_mtu == 1280 && simple.transport_mtu == 1500);
    auto omitted_listen = base;
    omitted_listen.erase("listen");
    const auto outbound_only = parse_config(omitted_listen.dump());
    CHECK(!outbound_only.listen.enabled && outbound_only.listen.bind_address.port == 0);
    roundtrip_policy(omitted_listen);
    const auto canonical = json::parse(serialize_config(simple));
    CHECK(!canonical.contains("endpoint"));
    CHECK(canonical.at("listen").at("bind_address") == "100.0.0.1:65535");
    CHECK(canonical.at("peers")[0].at("endpoint") == "100.0.0.2:65535");
    auto shorthand = base;
    shorthand["listen"]["bind_address"] = "100.0.0.1";
    shorthand["peers"][0]["endpoint"] = "100.0.0.2";
    const auto shorthand_config = parse_config(shorthand.dump());
    CHECK(shorthand_config.listen.bind_address.str() == "100.0.0.1:65535");
    CHECK(shorthand_config.peers[0].address.str() == "100.0.0.2:65535");
    auto shorthand_v6 = base;
    shorthand_v6["listen"]["bind_address"] = "fd00::1";
    shorthand_v6["peers"][0]["endpoint"] = "fd00::2";
    const auto shorthand_v6_config = parse_config(shorthand_v6.dump());
    CHECK(shorthand_v6_config.listen.bind_address.str() == "[fd00::1]:65535");
    CHECK(shorthand_v6_config.peers[0].address.str() == "[fd00::2]:65535");
    auto managed = base;
    managed["address_server"] = {
        {"address", "100.0.0.10:65534"},
        {"networks", {"10.90.0.0/24"}},
        {"clients", {{{"address", "100.0.0.3"}, {"shared_key", "managed-client-key"}, {"networks", {"10.90.0.0/24"}}}}}
    };
    const auto managed_config = parse_config(managed.dump());
    CHECK(managed_config.address_server.clients.size() == 1);
    CHECK(managed_config.address_server.clients[0].address.str() == "100.0.0.3:65535");
    roundtrip_policy(managed);
    roundtrip_policy(base);
#if defined(__linux__) && !defined(__ANDROID__)
    CHECK(simple.device_backend == "kernel");
#else
    CHECK(simple.device_backend == "tun");
#endif
    CHECK(Configure().device_backend == simple.device_backend);
    CHECK(canonical.at("device_backend") == simple.device_backend);

    auto d = base; d["listen"].erase("bind_address"); invalid_config(d);
    d = base; d["endpoint"] = "100.0.0.1:65535"; invalid_config(d);
    d = base; d["listen"]["address"] = "100.0.0.1:65535"; invalid_config(d);
    d = base; d["peers"][0]["address"] = "100.0.0.2:65535"; invalid_config(d);
    d = base; d["networks"][0] = {{"tunnel", "10.1.0.0/24"}, {"tunnel_ip", "10.1.0.2"}}; invalid_config(d);
    d = base; d["auto_key"] = true; invalid_config(d);
    d = base; d["listen"]["enabled"] = false; CHECK(!parse_config(d.dump()).listen.enabled); roundtrip_policy(d);
    d = base; d["listen"]["shared_key"] = "listen-admission-key";
    CHECK(parse_config(d.dump()).listen.shared_key == "listen-admission-key"); roundtrip_policy(d);
    d["listen"]["shared_key"] = ""; invalid_config(d);
    d = base; d["listen"]["bind_address"] = "0.0.0.0:65535"; CHECK(parse_config(d.dump()).listen.bind_address.ip.unspecified()); roundtrip_policy(d);
    d = base; d["listen"] = {{"enabled", false}};
    auto outbound_only_listen_flag = parse_config(d.dump());
    CHECK(!outbound_only_listen_flag.listen.enabled && outbound_only_listen_flag.listen.bind_address.ip.unspecified() && outbound_only_listen_flag.listen.bind_address.port == 0);
    roundtrip_policy(d);
    d = base; d["listen"]["bind_address"] = "100.0.0.1:65536"; invalid_config(d);
    d = base; d["peers"][0]["endpoint"] = "100.0.0.1:65535"; invalid_config(d);
    d = base; d["peers"][0]["shared_key"] = ""; invalid_config(d);
    d = base; d["peers"].push_back(d["peers"][0]); invalid_config(d);
    d = base; d["peers"][0]["networks"] = json::array(); invalid_config(d);
    d = base; d["peers"][0]["networks"] = {"10.2.0.0/24"}; invalid_config(d);
    d = base; d["peers"][0]["networks"] = {"10.1.0.2/24"}; invalid_config(d);
    d = base; d["listen"]["networks"] = {"10.2.0.0/24"}; invalid_config(d);
    d = base; d["listen"] = {{"enabled", false}, {"networks", json::array()}, {"bind_address", "127.0.0.1:45000"}, {"shared_key", "stale-listener-key"}};
    const auto disabled_bind = parse_config(d.dump());
    CHECK(disabled_bind.listen.bind_address.ip.unspecified() && disabled_bind.listen.bind_address.port == 0);
    CHECK(disabled_bind.listen.shared_key.empty());
    const auto disabled_bind_normalized = json::parse(serialize_config(disabled_bind));
    CHECK(disabled_bind_normalized["listen"] == json({{"enabled", false}, {"networks", json::array()}}));

    d = base; d.erase("peers"); CHECK(parse_config(d.dump()).peers.empty()); roundtrip_policy(d);
    d = base; d["listen"] = json::object(); invalid_config(d);
    d = base; d["obsolete_option"] = 1; invalid_config(d);
    d = base; d["tun_mtu"] = 1306; roundtrip_policy(d);
    d["tun_mtu"] = 1307; invalid_config(d);
    d = base; d["transport_mtu"] = 1600; d["tun_mtu"] = 1400; roundtrip_policy(d);
    d = base; d.erase("networks"); invalid_config(d);
    d = base; d["networks"] = json::array(); invalid_config(d);
    d = base; d["networks"] = nullptr; invalid_config(d);
    d = base; d["networks"] = {"10.1.0.2"}; invalid_config(d);
    d = base; d["networks"] = {"10.1.0.0/24"}; invalid_config(d);
    d = base; d["networks"] = {"10.1.0.255/24"}; invalid_config(d);
    d = base; d["networks"].push_back("10.1.0.3/24"); invalid_config(d);
    d = base; d["networks"].push_back("10.2.0.1/8"); invalid_config(d);
    d = base; d["peers"] = nullptr; invalid_config(d);
    d = base; d["peers"][0]["transport"] = "quic"; invalid_config(d);
    d = base; d["peers"][0]["transport"] = "tcp"; CHECK(parse_config(d.dump()).peers[0].transport == "tcp"); roundtrip_policy(d);
    d["peers"][0]["transport"] = "udp"; CHECK(json::parse(serialize_config(parse_config(d.dump())))["peers"][0]["transport"] == "udp");
    for (const auto& invalid_transport : json::array({"auto", "TCP", "", true, 1, nullptr, json::array(), json::object()})) {
        d["peers"][0]["transport"] = invalid_transport; invalid_config(d);
    }
    d = base; d["networks"].push_back("192.168.0.2/24"); invalid_config(d);
    d["peers"][0]["networks"] = {"10.1.0.0/24"}; roundtrip_policy(d);
    CHECK(parse_config(d.dump()).peers[0].networks.size() == 1);
    d["peers"].push_back({{"endpoint", "100.0.0.3:65535"}, {"shared_key", "different-peer-key"}, {"networks", {"10.1.0.0/24"}}}); roundtrip_policy(d);
    d = base; d["networks"] = json::array();
    for (unsigned i = 0; i < 64; ++i) d["networks"].push_back("172.20." + std::to_string(i) + ".1/24");
    d["peers"] = json::array(); CHECK(parse_config(d.dump()).networks.size() == 64); roundtrip_policy(d);
    d["networks"].push_back("172.20.64.1/24"); invalid_config(d);
    std::string error; Configure result;
    CHECK(!try_parse_config("{\"listen\":{},\"listen\":{}}", &result, &error));
    CHECK(error.find("duplicate") != std::string::npos);
    CHECK(!try_parse_config("[]", &result, &error));
    CHECK(!try_parse_config("{\"shared_key\": SECRET_SHOULD_NOT_APPEAR}", &result, &error));
    CHECK(error.find("SECRET_SHOULD_NOT_APPEAR") == std::string::npos);
    CHECK(!try_parse_config(base.dump(), nullptr, &error));
    CHECK(!try_parse_config(std::string(1048577, ' '), &result, &error));
    CHECK(error.find("1 MiB") != std::string::npos);
    CHECK(!try_parse_config(std::string(40, '[') + "0" + std::string(40, ']'), &result, &error));
    CHECK(error.find("nesting") != std::string::npos);
    d = base; d["peers"] = json::array();
    for (unsigned i = 0; i < 257; ++i) d["peers"].push_back(base["peers"][0]);
    invalid_config(d);
    CHECK(Network::parse("2001:db8:0:0::1/64") == Network::parse("2001:db8::/64"));
    CHECK(Endpoint::parse("[2001:0db8::1]:1234") == Endpoint::parse("[2001:db8::1]:1234"));
    auto invalid = simple; invalid.peers[0].networks[0].tunnel_ip = IpAddress::parse("10.1.0.3");
    bool rejected = false; try { serialize_config(invalid); } catch (const config_error&) { rejected = true; } CHECK(rejected);
    invalid = simple; invalid.peers[0].transport = "quic"; rejected = false;
    try { serialize_config(invalid); } catch (const config_error&) { rejected = true; } CHECK(rejected);
    CHECK(!try_parse_config(base.dump(), nullptr, &error));
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
    protocol::ForwardHeader h; h.network = network(); h.source = node_id(1); h.destination = node_id(4); h.flow_id = 1234; return h;
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
    h = header(); h.kind = protocol::PacketKind::Multicast; h.destination = NodeId();
    CHECK(protocol::decode(protocol::encode(h, packet), &parsed, &decoded));
}

PathAnnouncement route(const std::vector<NodeId>& path, unsigned key_value = 1) {
    PathAnnouncement result; result.network = network(); result.destination = node_id(4);
    result.tunnel_ip = IpAddress::parse("10.1.0.4"); result.public_key.fill(static_cast<unsigned char>(key_value)); result.path = path; return result;
}
void routing_tests() {
    const auto a = node(1), b = node(2), c = node(3), d = node(4), e = node(5);
    NetworkConfig local; local.tunnel = network(); local.tunnel_ip = IpAddress::parse("10.1.0.1");
    Gossip table({local}); table.authorize(b, {network()}); table.authorize(c, {network()});
    table.set_peer_nodes(b, {{network(), node_id(2)}}); table.set_peer_nodes(c, {{network(), node_id(3)}});
    CHECK(!table.announce(b, route({node_id(2), node_id(4)})));
    table.set_available(b, true); table.set_available(c, true);
    CHECK(table.announce(b, route({node_id(2), node_id(4)})));
    CHECK(table.announce(c, route({node_id(3), node_id(4)}, 2)));
    CHECK(table.next_hops(network(), node_id(4)).size() == 2);
    CHECK(table.accept_rpf(network(), node_id(4), b)); CHECK(!table.accept_rpf(network(), node_id(4), c));
    PublicKey key{}; CHECK(table.public_key(network(), node_id(4), &key)); CHECK(key[0] == 2);
    Endpoint selected, again; std::set<Endpoint> selected_peers;
    for (unsigned i = 0; i < 20; ++i) {
        CHECK(table.select_unicast(network(), node_id(4), i, &selected)); CHECK(table.select_unicast(network(), node_id(4), i, &again));
        CHECK(selected == again); selected_peers.insert(selected);
    }
    CHECK(selected_peers.size() == 2);
    CHECK(!table.announce(b, route({node_id(2), node_id(1), node_id(4)})));
    CHECK(!table.announce(b, route({node_id(2), node_id(3), node_id(2), node_id(4)})));
    CHECK(!table.announce(b, route({node_id(3), node_id(4)})));
    auto wrong = route({node_id(2), node_id(4)}); wrong.network = Network::parse("192.168.0.0/24");
    CHECK(!table.announce(b, wrong));
    wrong = route({node_id(2), node_id(4)}); wrong.destination = IpAddress::parse("fd00::4"); wrong.path.back() = wrong.destination;
    CHECK(!table.announce(b, wrong));
    wrong = route({node_id(2), node_id(4)}); wrong.destination = IpAddress::parse("10.2.0.4"); wrong.path.back() = wrong.destination;
    CHECK(!table.announce(b, wrong));
    wrong = route({node_id(2), IpAddress::parse("fd00::5"), node_id(4)});
    CHECK(!table.announce(b, wrong));
    wrong = route({node_id(2), IpAddress::parse("10.2.0.5"), node_id(4)});
    CHECK(!table.announce(b, wrong));
    wrong = route({node_id(2), node_id(4)}); wrong.tunnel_ip = local.tunnel_ip; CHECK(!table.announce(b, wrong));
    table.withdraw(c, network(), node_id(4)); CHECK(table.public_key(network(), node_id(4), &key)); CHECK(key[0] == 1);
    CHECK(table.announce(c, route({node_id(3), node_id(5), node_id(4)}, 3)));
    CHECK(table.next_hops(network(), node_id(4)) == std::vector<Endpoint>{b});
    // Losing adjacency A-B must not remove C's path merely because it contains B.
    CHECK(table.announce(c, route({node_id(3), node_id(2), node_id(4)}, 4)));
    table.set_available(b, false);
    CHECK(table.next_hops(network(), node_id(4)) == std::vector<Endpoint>{c});
    CHECK(table.public_key(network(), node_id(4), &key) && key[0] == 4);
    NodeId selected_node; CHECK(table.node_for_ip(network(), IpAddress::parse("10.1.0.4"), &selected_node) && selected_node == node_id(4));
    table.set_available(c, false); CHECK(table.size() == 0); CHECK(!table.public_key(network(), node_id(4), &key));
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
    if (family == 4) {
        // A wildcard listener must be able to pin a datagram to the local
        // address used by the authenticated control connection.  Without the
        // source override the route lookup is free to choose another address.
        EventLoop source_loop; bool source_received = false; Endpoint observed;
        Endpoint wildcard; wildcard.ip = IpAddress::parse("0.0.0.0");
        UdpTransport sender(source_loop, wildcard, max_payload, [](const Endpoint&, Bytes) {});
        Endpoint receiver_bind; receiver_bind.ip = IpAddress::parse("127.0.0.1");
        UdpTransport receiver(source_loop, receiver_bind, max_payload, [&](const Endpoint& remote, Bytes packet) {
            observed = remote; source_received = packet == Bytes{0x7f}; source_loop.breakLoop();
        });
        Endpoint source; source.ip = receiver_bind.ip;
        bool source_timeout = false;
        auto source_deadline = source_loop.addTimer(std::chrono::seconds(2), [&](evutil_socket_t, short) {
            source_timeout = true; source_loop.breakLoop();
        });
        CHECK(source_deadline); CHECK(sender.send(receiver.local_address(), Bytes{0x7f}, source));
        CHECK(source_loop.run() == 0); CHECK(source_received && !source_timeout && observed.ip == source.ip);
        // If the requested local address is unavailable, the transport must
        // retry with ordinary route-based source selection instead of dropping.
        EventLoop fallback_loop; bool fallback_received = false; Endpoint fallback_observed;
        UdpTransport fallback_sender(fallback_loop, wildcard, max_payload, [](const Endpoint&, Bytes) {});
        UdpTransport fallback_receiver(fallback_loop, receiver_bind, max_payload, [&](const Endpoint& remote, Bytes packet) {
            fallback_observed = remote; fallback_received = packet == Bytes{0x7e}; fallback_loop.breakLoop();
        });
        Endpoint unavailable; unavailable.ip = IpAddress::parse("192.0.2.1");
        bool fallback_timeout = false;
        auto fallback_deadline = fallback_loop.addTimer(std::chrono::seconds(2), [&](evutil_socket_t, short) {
            fallback_timeout = true; fallback_loop.breakLoop();
        });
        CHECK(fallback_deadline); CHECK(fallback_sender.send(fallback_receiver.local_address(), Bytes{0x7e}, unavailable));
        CHECK(fallback_loop.run() == 0); CHECK(fallback_received && !fallback_timeout && fallback_observed.ip != unavailable.ip);
    }
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