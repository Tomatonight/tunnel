#include "gossip.h"
#include "parse_config.h"
#include "return_flows.h"
#include "wire.h"
#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <set>
#include <stdexcept>

namespace {
unsigned checks = 0;
void check(bool value, const char* expression, unsigned line) {
    ++checks;
    if (!value) throw std::runtime_error(std::string("line ") + std::to_string(line) + ": " + expression);
}
#define CHECK(value) check(bool(value), #value, __LINE__)
using Json = wire::Json;
Endpoint node(unsigned n) { return Endpoint::parse("100.0.0." + std::to_string(n) + ":65535"); }
Network subnet(const char* text) { return Network::parse(text); }
const Network overlay = subnet("10.1.0.0/16"), overlay2 = subnet("10.3.0.0/16");
const Network lan = subnet("10.2.0.0/16"), other_lan = subnet("10.4.0.0/16");
NetworkConfig local(const Network& network, const char* ip) {
    NetworkConfig result; result.tunnel = network; result.tunnel_ip = IpAddress::parse(ip); return result;
}
AdvertisedRoute advertised(const Network& network, const Network& prefix) {
    AdvertisedRoute result; result.tunnel = network; result.prefix = prefix; return result;
}
PathAnnouncement announcement(const Network& network, unsigned destination, const char* ip,
                              std::vector<Endpoint> path, std::vector<Network> prefixes = {lan}) {
    PathAnnouncement a; a.network = network; a.destination = node(destination); a.tunnel_ip = IpAddress::parse(ip);
    a.public_key[0] = static_cast<unsigned char>(destination); a.path = path; a.prefixes = prefixes; return a;
}
void available(Gossip& table, unsigned peer, const std::vector<Network>& networks = {overlay}) {
    table.authorize(node(peer), networks); table.set_available(node(peer), true);
}
void rejected(const Json& value) {
    Configure config; std::string error;
    CHECK(!try_parse_config(value.dump(), &config, &error)); CHECK(!error.empty());
}
void throws(const std::function<void()>& fn) {
    bool rejected = false; try { fn(); } catch (const std::exception&) { rejected = true; } CHECK(rejected);
}
Json config_base() {
    return {{"address", node(1).str()}, {"networks", {"10.1.0.1/16"}},
            {"advertise_routes", {{{"tunnel", overlay.str()}, {"prefix", lan.str()}, {"snat", true}}}}};
}
void configuration_tests() {
    auto doc = config_base(); auto config = parse_config(doc.dump());
    CHECK(config.advertise_routes.size() == 1); CHECK(config.advertise_routes[0].snat);
    CHECK(config.advertise_routes[0].tunnel == overlay); CHECK(config.advertise_routes[0].prefix == lan);
    const auto normalized = serialize_config(config); auto copy = parse_config(normalized);
    CHECK(copy.advertise_routes.size() == 1 && copy.advertise_routes[0].snat);
    CHECK(serialize_config(copy) == normalized);
    doc["advertise_routes"][0].erase("snat"); CHECK(!parse_config(doc.dump()).advertise_routes[0].snat);
    CHECK(!Json::parse(serialize_config(parse_config(doc.dump())))["advertise_routes"][0].count("snat"));
    doc["advertise_routes"] = Json::array(); CHECK(parse_config(doc.dump()).advertise_routes.empty());
    for (const auto* prefix : {"10.2.0.1/16", "0.0.0.0/0", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "128.0.0.0/1", "fd01::/64", "10.1.0.0/16", "10.0.0.0/8", "10.1.1.0/24"}) {
        doc = config_base(); doc["advertise_routes"][0]["prefix"] = prefix; rejected(doc);
    }
    doc = config_base(); doc["advertise_routes"][0]["tunnel"] = "10.1.0.1/16"; rejected(doc);
    doc = config_base(); doc["advertise_routes"][0]["tunnel"] = "10.9.0.0/16"; rejected(doc);
    doc = config_base(); doc["advertise_routes"][0]["snat"] = 1; rejected(doc);
    doc = config_base(); doc["advertise_routes"][0]["dnat"] = true; rejected(doc);
    doc = config_base(); doc["advertise_routes"] = "10.2.0.0/16"; rejected(doc);
    doc = config_base(); doc["advertise_routes"].push_back(doc["advertise_routes"][0]); rejected(doc);
    doc = config_base(); doc["advertise_routes"].push_back({{"tunnel", overlay.str()}, {"prefix", "10.2.1.0/24"}}); rejected(doc);
    doc = config_base(); doc["networks"].push_back("10.3.0.1/16");
    doc["advertise_routes"].push_back({{"tunnel", overlay2.str()}, {"prefix", lan.str()}}); rejected(doc);
    doc = config_base(); doc["networks"].push_back("10.2.1.1/24"); rejected(doc);
    doc = config_base(); doc["advertise_routes"] = Json::array();
    for (unsigned i = 0; i < 64; ++i) doc["advertise_routes"].push_back({{"tunnel", overlay.str()}, {"prefix", "172.16." + std::to_string(i) + ".0/24"}});
    CHECK(parse_config(doc.dump()).advertise_routes.size() == 64);
    doc["advertise_routes"].push_back({{"tunnel", overlay.str()}, {"prefix", "172.17.0.0/24"}}); rejected(doc);
    doc = config_base(); doc["networks"] = {"fd00::1/64"};
    doc["advertise_routes"] = {{{"tunnel", "fd00::/64"}, {"prefix", "fd01::/64"}}};
    CHECK(parse_config(doc.dump()).advertise_routes[0].prefix == subnet("fd01::/64"));
    doc["advertise_routes"][0]["prefix"] = "::/1"; rejected(doc);
    doc["advertise_routes"][0]["prefix"] = "ff00::/8"; rejected(doc);
    doc = config_base(); doc.erase("networks");
    doc["address_clients"] = {{{"address", node(9).str()}, {"shared_key", "allocator-key"}, {"networks", {overlay.str()}}}};
    config = parse_config(doc.dump()); CHECK(config.networks[0].tunnel_ip.unspecified());
    CHECK(parse_config(serialize_config(config)).advertise_routes[0].prefix == lan);
    doc["advertise_routes"][0]["prefix"] = "10.1.1.0/24"; rejected(doc);
    doc = {{"peers", Json::array()}, {"advertise_routes", config_base()["advertise_routes"]}};
    doc["listen"] = {{"enabled", true}, {"address", node(1).str()}};
    doc["listen"]["networks"] = Json::array({{{"tunnel", overlay.str()}, {"tunnel_ip", "10.1.0.1"}}});
    CHECK(parse_config(doc.dump()).advertise_routes[0].snat);
    doc = {{"address_server", {{"address", node(9).str()}, {"shared_key", "allocator-key"}, {"networks", {overlay.str()}}}},
           {"advertise_routes", config_base()["advertise_routes"]}}; rejected(doc);
    doc["advertise_routes"] = Json::array(); CHECK(parse_config(doc.dump()).advertise_routes.empty());
    auto invalid = subnet("10.2.0.0/16"); invalid.address = IpAddress::parse("10.2.1.1"); CHECK(!valid_advertised_prefix(invalid));
    CHECK(valid_advertised_prefix(subnet("10.2.3.4/32"))); CHECK(valid_advertised_prefix(subnet("fd01::1/128")));
}
void wire_tests() {
    const auto a = announcement(overlay, 2, "10.1.0.2", {node(2)});
    auto doc = wire::route(a); CHECK(wire::route(doc).prefixes == a.prefixes);
    doc.erase("prefixes"); CHECK(wire::route(doc).prefixes.empty());
    doc["prefixes"] = Json::array(); CHECK(wire::route(doc).prefixes.empty());
    for (const auto* prefix : {"10.2.0.1/16", "0.0.0.0/0", "224.0.0.0/4", "240.0.0.0/4", "128.0.0.0/1", "fd01::/64", "10.1.0.0/16", "10.0.0.0/8"}) {
        doc = wire::route(a); doc["prefixes"] = {prefix}; throws([&]() { wire::route(doc); });
    }
    doc = wire::route(a); doc["prefixes"] = {lan.str(), lan.str()}; throws([&]() { wire::route(doc); });
    doc["prefixes"] = {lan.str(), "10.2.1.0/24"}; throws([&]() { wire::route(doc); });
    doc["prefixes"] = lan.str(); throws([&]() { wire::route(doc); });
    doc["prefixes"] = {nullptr}; throws([&]() { wire::route(doc); });
    doc["prefixes"] = Json::array();
    for (unsigned i = 0; i < 64; ++i) doc["prefixes"].push_back("172.16." + std::to_string(i) + ".0/24");
    CHECK(wire::route(doc).prefixes.size() == 64);
    doc["prefixes"].push_back("172.17.0.0/24"); throws([&]() { wire::route(doc); });
    auto six = announcement(subnet("fd00::/64"), 2, "fd00::2", {node(2)}, {subnet("fd01::/64")});
    CHECK(wire::route(wire::route(six)).prefixes == six.prefixes);
}
void gossip_tests() {
    const auto a = node(1), b = node(2), c = node(3), d = node(4), e = node(5);
    Gossip table(a, {local(overlay, "10.1.0.1")});
    available(table, 2); available(table, 3); available(table, 5);
    CHECK(table.announce(b, announcement(overlay, 4, "10.1.0.4", {b, d})));
    CHECK(table.advertised_prefixes(overlay) == std::vector<Network>{lan});
    CHECK(table.prefixes_for_node(overlay, d) == std::vector<Network>{lan});
    CHECK(table.prefixes_for_node(overlay, c).empty());
    Endpoint gateway; CHECK(table.select_gateway(overlay, lan, &gateway) && gateway == d);
    CHECK(!table.select_gateway(overlay, lan, nullptr));
    CHECK(!table.select_gateway(overlay, other_lan, &gateway));
    auto forwarded = table.export_to(e); CHECK(forwarded.size() == 1);
    CHECK(forwarded[0].prefixes == std::vector<Network>{lan});
    CHECK(forwarded[0].path == std::vector<Endpoint>({a, b, d}));
    Gossip downstream(e, {local(overlay, "10.1.0.5")}); available(downstream, 1);
    CHECK(downstream.announce(a, wire::route(wire::route(forwarded[0]))));
    CHECK(downstream.select_gateway(overlay, lan, &gateway) && gateway == d);
    CHECK(downstream.next_hops(overlay, d) == std::vector<Endpoint>{a});
    CHECK(table.announce(c, announcement(overlay, 4, "10.1.0.4", {c, d})));
    CHECK(table.next_hops(overlay, d) == std::vector<Endpoint>({b, c}));
    CHECK(table.select_gateway(overlay, lan, &gateway) && gateway == d);
    std::set<Endpoint> choices;
    for (unsigned i = 0; i < 64; ++i) { Endpoint peer; CHECK(table.select_unicast(overlay, d, i, &peer)); choices.insert(peer); }
    CHECK(choices.size() == 2);
    table.set_available(b, false); CHECK(table.select_gateway(overlay, lan, &gateway) && gateway == d);
    CHECK(table.next_hops(overlay, d) == std::vector<Endpoint>{c});
    CHECK(table.announce(c, announcement(overlay, 3, "10.1.0.3", {c})));
    CHECK(table.select_gateway(overlay, lan, &gateway) && gateway == c);
    table.withdraw(c, overlay, c); CHECK(table.select_gateway(overlay, lan, &gateway) && gateway == d);
    available(table, 2);
    CHECK(table.announce(b, announcement(overlay, 2, "10.1.0.2", {b})));
    CHECK(table.announce(c, announcement(overlay, 3, "10.1.0.3", {c})));
    CHECK(table.select_gateway(overlay, lan, &gateway) && gateway == b);
    table.withdraw(b, overlay, b); CHECK(table.select_gateway(overlay, lan, &gateway) && gateway == c);
    CHECK(table.prefixes_for_node(overlay, d) == std::vector<Network>{lan}); // Standby still identifies its LAN source.
    table.set_authorized_networks(c, {}); CHECK(table.advertised_prefixes(overlay).empty());
    CHECK(table.next_hops(overlay, d).empty());
    downstream.withdraw(a, overlay, d); CHECK(downstream.advertised_prefixes(overlay).empty());

    // A newer empty list removes the origin's attributes on every export path.
    Gossip updated(a, {local(overlay, "10.1.0.1")}); available(updated, 2); available(updated, 3); available(updated, 5);
    CHECK(updated.announce(b, announcement(overlay, 4, "10.1.0.4", {b, d})));
    CHECK(updated.snapshot()[0].prefixes == std::vector<Network>{lan});
    CHECK(updated.announce(c, announcement(overlay, 4, "10.1.0.4", {c, d}, {})));
    CHECK(updated.prefixes_for_node(overlay, d).empty()); CHECK(updated.export_to(e)[0].prefixes.empty());
    CHECK(updated.snapshot()[0].prefixes.empty());
    CHECK(updated.next_hops(overlay, d).size() == 2);
    CHECK(updated.announce(b, announcement(overlay, 4, "10.1.0.4", {b, d}, {other_lan})));
    CHECK(updated.prefixes_for_node(overlay, d) == std::vector<Network>{other_lan});
    CHECK(updated.snapshot()[0].prefixes == std::vector<Network>{other_lan});
    auto replacement = announcement(overlay, 4, "10.1.0.4", {c, d}); replacement.public_key[0] = 41;
    CHECK(updated.announce(c, replacement));
    CHECK(updated.snapshot()[0].prefixes == std::vector<Network>{lan});
    CHECK(updated.snapshot()[0].public_key == replacement.public_key);
    CHECK(updated.export_to(e)[0].prefixes == updated.snapshot()[0].prefixes);
    updated.withdraw(c, overlay, d);
    CHECK(updated.snapshot()[0].prefixes == std::vector<Network>{other_lan});
    CHECK(updated.select_gateway(overlay, other_lan, &gateway) && gateway == d);
    CHECK(!updated.select_gateway(overlay, lan, &gateway));
    // Two destinations advertise the same LAN. A newer direct publisher takes
    // over, and its withdrawal restores the still-announced multihop standby.
    CHECK(updated.announce(c, announcement(overlay, 3, "10.1.0.3", {c}, {other_lan})));
    CHECK(updated.snapshot().size() == 2);
    for (const auto& a : updated.snapshot()) CHECK(a.prefixes == std::vector<Network>{other_lan});
    CHECK(updated.select_gateway(overlay, other_lan, &gateway) && gateway == c);
    updated.withdraw(c, overlay, c);
    CHECK(updated.snapshot().size() == 1 && updated.snapshot()[0].prefixes == std::vector<Network>{other_lan});
    CHECK(updated.select_gateway(overlay, other_lan, &gateway) && gateway == d);
    updated.set_local_address(overlay, nullptr); CHECK(updated.advertised_prefixes(overlay).empty());

    // Invalid wire-like input cannot partially replace a valid stored record.
    Gossip invalid(a, {local(overlay, "10.1.0.1")}); available(invalid, 2);
    auto good = announcement(overlay, 2, "10.1.0.2", {b}); CHECK(invalid.announce(b, good));
    for (const auto& prefix : {subnet("0.0.0.0/0"), subnet("224.0.0.0/4"), overlay, subnet("fd01::/64")}) {
        auto bad = good; bad.prefixes = {prefix}; CHECK(!invalid.announce(b, bad));
        CHECK(invalid.prefixes_for_node(overlay, b) == std::vector<Network>{lan});
    }
    auto bad = good; bad.prefixes.assign(65, lan); CHECK(!invalid.announce(b, bad));
    bad = good; bad.prefixes = {lan, lan}; CHECK(!invalid.announce(b, bad));
    bad.prefixes = {lan, subnet("10.2.1.0/24")}; CHECK(!invalid.announce(b, bad));
}
void conflict_tests() {
    const auto a = node(1), b = node(2), c = node(3);
    Gossip table(a, {local(overlay, "10.1.0.1"), local(overlay2, "10.3.0.1")});
    available(table, 2, {overlay, overlay2}); available(table, 3, {overlay, overlay2});
    CHECK(table.announce(b, announcement(overlay, 2, "10.1.0.2", {b})));
    CHECK(table.announce(c, announcement(overlay2, 3, "10.3.0.3", {c})));
    CHECK(table.advertised_prefixes(overlay).empty()); CHECK(table.advertised_prefixes(overlay2).empty());
    CHECK(table.next_hops(overlay, b) == std::vector<Endpoint>{b});
    CHECK(table.next_hops(overlay2, c) == std::vector<Endpoint>{c});
    CHECK(table.snapshot().size() == 2 && !table.snapshot()[0].prefixes.empty());
    table.withdraw(c, overlay2, c); CHECK(table.advertised_prefixes(overlay) == std::vector<Network>{lan});
    CHECK(table.announce(c, announcement(overlay, 3, "10.1.0.3", {c}, {subnet("10.2.1.0/24"), other_lan})));
    CHECK(table.prefixes_for_node(overlay, b).empty());
    CHECK(table.prefixes_for_node(overlay, c) == std::vector<Network>{other_lan});
    CHECK(table.next_hops(overlay, b).size() == 1 && table.next_hops(overlay, c).size() == 1);
    table.withdraw(b, overlay, b);
    CHECK(table.prefixes_for_node(overlay, c) == std::vector<Network>({subnet("10.2.1.0/24"), other_lan}));
    // A prefix covering a different local tunnel is unusable, while ordinary
    // reachability to its publisher stays intact.
    CHECK(table.announce(b, announcement(overlay, 2, "10.1.0.2", {b}, {overlay2})));
    CHECK(table.prefixes_for_node(overlay, b).empty()); CHECK(table.next_hops(overlay, b).size() == 1);

    const auto own = advertised(overlay, lan);
    Gossip local_table(a, {local(overlay, "10.1.0.1"), local(overlay2, "10.3.0.1")}, {own});
    available(local_table, 2, {overlay, overlay2});
    CHECK(local_table.prefixes_for_node(overlay, a).empty()); // Backend must activate first.
    CHECK(local_table.announce(b, announcement(overlay2, 2, "10.3.0.2", {b})));
    CHECK(local_table.prefixes_for_node(overlay2, b).empty()); // Inactive local LAN still reserved.
    local_table.withdraw(b, overlay2, b); local_table.set_local_prefixes(overlay, {lan});
    CHECK(local_table.prefixes_for_node(overlay, a) == std::vector<Network>{lan});
    Endpoint gateway; CHECK(local_table.select_gateway(overlay, lan, &gateway) && gateway == a);
    CHECK(local_table.announce(b, announcement(overlay2, 2, "10.3.0.2", {b})));
    CHECK(local_table.prefixes_for_node(overlay, a).empty());
    CHECK(local_table.active_local_prefixes(overlay) == std::vector<Network>{lan});
    local_table.withdraw(b, overlay2, b);
    CHECK(local_table.announce(b, announcement(overlay, 2, "10.1.0.2", {b})));
    CHECK(local_table.select_gateway(overlay, lan, &gateway) && gateway == a);
    local_table.set_local_prefixes(overlay, {});
    CHECK(local_table.select_gateway(overlay, lan, &gateway) && gateway == b);
    throws([&]() { local_table.set_local_prefixes(overlay, {other_lan}); });
    local_table.set_local_address(overlay, nullptr); CHECK(local_table.advertised_prefixes(overlay).empty());
    throws([&]() { local_table.set_local_prefixes(overlay, {lan}); });

    // Pending managed tunnel ranges also reserve their address space.
    auto pending = local(overlay2, "10.3.0.1"); pending.tunnel_ip.bytes.fill(0); pending.allocation_server = node(9);
    Gossip managed(a, {local(overlay, "10.1.0.1"), pending}); available(managed, 2);
    CHECK(managed.announce(b, announcement(overlay, 2, "10.1.0.2", {b}, {overlay2})));
    CHECK(managed.prefixes_for_node(overlay, b).empty()); CHECK(managed.next_hops(overlay, b).size() == 1);
    const auto assigned = IpAddress::parse("10.3.0.1"); managed.set_local_address(overlay2, &assigned);
    CHECK(managed.prefixes_for_node(overlay, b).empty());
}
void u16(Bytes& bytes, std::size_t offset, unsigned value) {
    bytes[offset] = static_cast<unsigned char>(value >> 8); bytes[offset + 1] = static_cast<unsigned char>(value);
}
Bytes packet(const char* source, const char* destination, unsigned protocol, const Bytes& body,
             unsigned fragments = 0, unsigned id = 123) {
    const auto from = IpAddress::parse(source), to = IpAddress::parse(destination); CHECK(from.family == to.family);
    Bytes result(from.family == 4 ? 20 : 40, 0);
    if (from.family == 4) {
        result[0] = 0x45; u16(result, 2, static_cast<unsigned>(20 + body.size())); u16(result, 4, id); u16(result, 6, fragments);
        result[8] = 64; result[9] = static_cast<unsigned char>(protocol);
        std::copy_n(from.bytes.begin(), 4, result.begin() + 12); std::copy_n(to.bytes.begin(), 4, result.begin() + 16);
    } else {
        result[0] = 0x60; u16(result, 4, static_cast<unsigned>(body.size())); result[6] = static_cast<unsigned char>(protocol); result[7] = 64;
        std::copy_n(from.bytes.begin(), 16, result.begin() + 8); std::copy_n(to.bytes.begin(), 16, result.begin() + 24);
    }
    result.insert(result.end(), body.begin(), body.end()); return result;
}
Bytes transport(unsigned source, unsigned destination, bool tcp = false) {
    Bytes body(tcp ? 20 : 8, 0); u16(body, 0, source); u16(body, 2, destination);
    if (tcp) { body[12] = 0x50; body[13] = 0x10; } else u16(body, 4, 8);
    return body;
}
Bytes echo(unsigned type, unsigned id = 123) {
    Bytes result(8, 0); result[0] = static_cast<unsigned char>(type); u16(result, 4, id); u16(result, 6, 1); return result;
}
Bytes fragment6(const char* source, const char* destination, unsigned next, const Bytes& body,
                unsigned flags, unsigned id) {
    Bytes fragment(8, 0); fragment[0] = static_cast<unsigned char>(next); u16(fragment, 2, flags);
    for (unsigned i = 0; i < 4; ++i) fragment[4 + i] = static_cast<unsigned char>(id >> (24 - i * 8));
    fragment.insert(fragment.end(), body.begin(), body.end());
    return packet(source, destination, 44, fragment);
}
void return_flow_tests() {
    const auto now = ReturnFlows::Time(std::chrono::hours(500000)); const auto gateway = node(2), backup = node(3);
    const auto udp = packet("10.1.0.1", "10.2.0.9", 17, transport(32000, 53));
    const auto udp_reply = packet("10.2.0.9", "10.1.0.1", 17, transport(53, 32000));
    ReturnFlows flows; Endpoint peer; IpAddress requested; bool related = true;
    CHECK(!flows.reply(udp_reply, &peer, &related, now)); CHECK(!flows.request_peer(udp, &peer, now));
    CHECK(flows.remember(udp, gateway, now)); CHECK(flows.size() == 1);
    CHECK(flows.request_peer(udp, &peer, now) && peer == gateway);
    CHECK(flows.reply(udp_reply, &peer, &related, now, &requested) && peer == gateway && !related);
    CHECK(requested == IpAddress::parse("10.2.0.9"));
    CHECK(!flows.reply(packet("10.2.0.8", "10.1.0.1", 17, transport(53, 32000)), &peer, nullptr, now));
    CHECK(!flows.reply(packet("10.2.0.9", "10.1.0.2", 17, transport(53, 32000)), &peer, nullptr, now));
    CHECK(!flows.reply(packet("10.2.0.9", "10.1.0.1", 17, transport(54, 32000)), &peer, nullptr, now));
    CHECK(!flows.reply(packet("10.2.0.9", "10.1.0.1", 17, transport(53, 32001)), &peer, nullptr, now));
    CHECK(!flows.reply(packet("10.2.0.9", "10.1.0.1", 6, transport(53, 32000, true)), &peer, nullptr, now));
    CHECK(!flows.reply(udp, &peer, nullptr, now)); CHECK(!flows.reply(udp_reply, nullptr, nullptr, now));
    CHECK(!flows.reply(udp_reply, &peer, nullptr, now + std::chrono::seconds(120)));
    flows.expire(now + std::chrono::seconds(120)); CHECK(flows.size() == 0);
    const auto tcp = packet("10.1.0.1", "10.2.0.9", 6, transport(32000, 443, true));
    const auto tcp_reply = packet("10.2.0.9", "10.1.0.1", 6, transport(443, 32000, true));
    CHECK(flows.remember(tcp, gateway, now));
    auto tcp_body = transport(443, 32000, true); tcp_body[13] = 2;
    CHECK(!flows.reply(packet("10.2.0.9", "10.1.0.1", 6, tcp_body), &peer, nullptr, now));
    tcp_body[13] = 18; CHECK(flows.reply(packet("10.2.0.9", "10.1.0.1", 6, tcp_body), &peer, nullptr, now));
    tcp_body.resize(8); CHECK(!flows.reply(packet("10.2.0.9", "10.1.0.1", 6, tcp_body), &peer, nullptr, now));
    // An ICMP error may quote only the first eight bytes of an initiating SYN.
    auto syn = tcp; syn[33] = 2; Bytes tcp_error(8, 0); tcp_error[0] = 3;
    tcp_error.insert(tcp_error.end(), syn.begin(), syn.begin() + 28);
    CHECK(flows.reply(packet("10.2.0.254", "10.1.0.1", 1, tcp_error), &peer, &related, now) && related);
    CHECK(flows.reply(tcp_reply, &peer, nullptr, now + std::chrono::seconds(300)));
    CHECK(!flows.reply(tcp_reply, &peer, nullptr, now + std::chrono::seconds(7500)));
    flows.clear(); CHECK(flows.size() == 0);
    for (unsigned family : {4u, 6u}) {
        const auto from = family == 4 ? "10.1.0.1" : "fd00::1";
        const auto to = family == 4 ? "10.2.0.9" : "fd01::9";
        const auto protocol = family == 4 ? 1u : 58u;
        const auto request = packet(from, to, protocol, echo(family == 4 ? 8 : 128));
        const auto response = packet(to, from, protocol, echo(family == 4 ? 0 : 129));
        CHECK(!flows.reply(response, &peer, nullptr, now)); CHECK(flows.remember(request, gateway, now));
        CHECK(flows.reply(response, &peer, &related, now) && !related && peer == gateway);
        CHECK(!flows.reply(packet(to, from, protocol, echo(family == 4 ? 0 : 129, 999)), &peer, nullptr, now));
        CHECK(!flows.reply(packet(to, from, protocol, echo(family == 4 ? 8 : 128)), &peer, nullptr, now));
        CHECK(!flows.reply(response, &peer, nullptr, now + std::chrono::seconds(30)));
        flows.clear();
        const auto request_udp = packet(from, to, 17, transport(32000, 53));
        CHECK(flows.remember(request_udp, gateway, now));
        Bytes error(8, 0); error[0] = static_cast<unsigned char>(family == 4 ? 3 : 1);
        error.insert(error.end(), request_udp.begin(), request_udp.end());
        const auto router = family == 4 ? "10.2.0.254" : "fd01::ffff";
        CHECK(flows.reply(packet(router, from, protocol, error), &peer, &related, now + std::chrono::seconds(119), &requested));
        CHECK(related && peer == gateway && requested == IpAddress::parse(to));
        CHECK(!flows.reply(packet(router, from, protocol, error), &peer, &related, now + std::chrono::seconds(120)));
        CHECK(!flows.reply(packet(router, family == 4 ? "10.1.0.2" : "fd00::2", protocol, error), &peer, nullptr, now));
        error[8 + (family == 4 ? 20 : 40)] ^= 1;
        CHECK(!flows.reply(packet(router, from, protocol, error), &peer, nullptr, now));
        flows.clear();
    }
    ReturnFlows capacity(1); CHECK(capacity.remember(udp, gateway, now));
    CHECK(!capacity.remember(tcp, backup, now)); CHECK(capacity.size() == 1);
    CHECK(capacity.remember(udp, backup, now)); CHECK(capacity.request_peer(udp, &peer, now) && peer == backup);
    CHECK(capacity.remember(tcp, gateway, now + std::chrono::seconds(121)));
    CHECK(capacity.size() == 1); capacity.erase_peer(gateway); CHECK(capacity.size() == 0);
    ReturnFlows disabled(0); CHECK(!disabled.remember(udp, gateway, now));
    CHECK(!flows.remember({}, gateway, now)); CHECK(!flows.remember(udp, Endpoint{}, now));
    CHECK(!flows.remember(packet("10.1.0.1", "10.2.0.9", 47, Bytes(8)), gateway, now));

    // Later IPv4 fragments require the matching, direction-specific first fragment.
    const auto first = packet("10.1.0.1", "10.2.0.9", 17, transport(32000, 53), 0x2000, 42);
    const auto later = packet("10.1.0.1", "10.2.0.9", 17, Bytes(8), 1, 42);
    const auto response_first = packet("10.2.0.9", "10.1.0.1", 17, transport(53, 32000), 0x2000, 73);
    const auto response_later = packet("10.2.0.9", "10.1.0.1", 17, Bytes(8), 1, 73);
    CHECK(!flows.remember(later, gateway, now)); CHECK(!flows.reply(response_later, &peer, nullptr, now));
    CHECK(flows.remember(first, gateway, now)); CHECK(flows.remember(later, gateway, now));
    CHECK(!flows.remember(later, backup, now)); CHECK(flows.request_peer(later, &peer, now) && peer == gateway);
    CHECK(!flows.reply(later, &peer, nullptr, now));
    CHECK(flows.reply(response_first, &peer, nullptr, now)); CHECK(flows.reply(response_later, &peer, nullptr, now));
    CHECK(!flows.reply(packet("10.2.0.9", "10.1.0.1", 17, Bytes(8), 1, 74), &peer, nullptr, now));
    CHECK(!flows.request_peer(later, &peer, now + std::chrono::seconds(30)));
    CHECK(!flows.reply(response_later, &peer, nullptr, now + std::chrono::seconds(30)));
    flows.erase_peer(gateway); CHECK(!flows.request_peer(first, &peer, now)); CHECK(!flows.reply(response_first, &peer, nullptr, now));

    // IPv6 destination options after Fragment must be traversed on the first
    // fragment, but kept as the cache discriminator for all subsequent pieces.
    flows.clear(); Bytes options(8, 0); options[0] = 17;
    auto request_options = options, reply_options = options;
    const auto request_ports = transport(32000, 53), reply_ports = transport(53, 32000);
    request_options.insert(request_options.end(), request_ports.begin(), request_ports.end());
    reply_options.insert(reply_options.end(), reply_ports.begin(), reply_ports.end());
    const auto first6 = fragment6("fd00::1", "fd01::9", 60, request_options, 1, 0x12345678);
    const auto later6 = fragment6("fd00::1", "fd01::9", 60, Bytes(8), 16, 0x12345678);
    const auto reply_first6 = fragment6("fd01::9", "fd00::1", 60, reply_options, 1, 0x87654321);
    const auto reply_later6 = fragment6("fd01::9", "fd00::1", 60, Bytes(8), 16, 0x87654321);
    CHECK(!flows.request_peer(later6, &peer, now)); CHECK(!flows.reply(reply_later6, &peer, nullptr, now));
    CHECK(flows.remember(first6, gateway, now)); CHECK(flows.request_peer(later6, &peer, now) && peer == gateway);
    CHECK(flows.remember(later6, gateway, now)); CHECK(!flows.remember(later6, backup, now));
    CHECK(!flows.reply(later6, &peer, nullptr, now));
    CHECK(flows.reply(reply_first6, &peer, &related, now) && !related && peer == gateway);
    CHECK(flows.reply(reply_later6, &peer, nullptr, now)); CHECK(!flows.request_peer(reply_later6, &peer, now));
    CHECK(!flows.request_peer(fragment6("fd00::1", "fd01::9", 60, Bytes(8), 16, 0x12345679), &peer, now));
    CHECK(!flows.reply(fragment6("fd01::9", "fd00::1", 60, Bytes(8), 16, 0x87654322), &peer, nullptr, now));
    CHECK(!flows.request_peer(fragment6("fd00::1", "fd01::9", 17, Bytes(8), 16, 0x12345678), &peer, now));
    CHECK(!flows.reply(fragment6("fd01::9", "fd00::1", 17, Bytes(8), 16, 0x87654321), &peer, nullptr, now));
    CHECK(!flows.reply(reply_later6, &peer, nullptr, now + std::chrono::seconds(30)));
    flows.clear();
    const auto atomic = fragment6("fd00::1", "fd01::9", 60, request_options, 0, 0x12345678);
    const auto atomic_reply = fragment6("fd01::9", "fd00::1", 60, reply_options, 0, 0x87654321);
    CHECK(flows.remember(atomic, gateway, now)); CHECK(flows.reply(atomic_reply, &peer, nullptr, now));
    CHECK(!flows.request_peer(later6, &peer, now)); CHECK(!flows.reply(reply_later6, &peer, nullptr, now));
    // Duplicate and truncated Fragment/extension headers are rejected.
    Bytes duplicate(8, 0); duplicate[0] = 17; duplicate.insert(duplicate.end(), request_ports.begin(), request_ports.end());
    CHECK(!flows.remember(fragment6("fd00::1", "fd01::9", 44, duplicate, 1, 1), gateway, now));
    CHECK(!flows.remember(packet("fd00::1", "fd01::9", 44, Bytes(4)), gateway, now));
    options[1] = 10;
    CHECK(!flows.remember(fragment6("fd00::1", "fd01::9", 60, options, 1, 1), gateway, now));
}
}
int main() {
    try {
        configuration_tests(); wire_tests(); gossip_tests(); conflict_tests(); return_flow_tests();
        std::cout << "subnet tests: " << checks << " checks passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "subnet tests failed: " << error.what() << '\n'; return 1; }
}
