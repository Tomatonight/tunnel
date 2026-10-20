#include "address_service.h"
#include <chrono>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <limits>
#include <stdexcept>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace {
using Json = wire::Json;
unsigned checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)
template<class F> void rejects(F f) { bool rejected = false; try { f(); } catch (const std::exception&) { rejected = true; } CHECK(rejected); }
void spin(EventLoop& loop, unsigned ms) {
    auto end = loop.addTimer(std::chrono::milliseconds(ms), [&](evutil_socket_t, short) { loop.breakLoop(); }); loop.run();
}
void until(EventLoop& loop, std::function<bool()> predicate, unsigned ms = 5000) {
    auto poll = loop.addTimer(std::chrono::milliseconds(10), [&](evutil_socket_t, short) { if (predicate()) loop.breakLoop(); }, true);
    auto end = loop.addTimer(std::chrono::milliseconds(ms), [&](evutil_socket_t, short) { loop.breakLoop(); }); loop.run(); CHECK(predicate());
}
void clean(const std::string& path) { std::remove(path.c_str()); std::remove((path + ".tmp").c_str()); std::remove((path + ".lock").c_str()); }
void write_file(const std::string& path, const std::string& value) { std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc); out << value; out.close(); CHECK(bool(out)); }
std::string read_file(const std::string& path) { std::ifstream in(path.c_str(), std::ios::binary); CHECK(bool(in)); return std::string(std::istreambuf_iterator<char>(in), {}); }
std::vector<Endpoint> ports(unsigned count) {
    struct Reservations {
        std::vector<evutil_socket_t> sockets;
        ~Reservations() { for (auto fd : sockets) evutil_closesocket(fd); }
    } held;
    // Keep advertised listeners outside the usual dynamic TCP source range.
    // Probe both protocols without reuse so occupied/TIME_WAIT ports are skipped.
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
Json client_entry(const Endpoint& e, unsigned id, const Json& nets) { return {{"address", e.str()}, {"shared_key", "test-only-allocation-key-" + std::to_string(id)}, {"networks", nets}}; }
Configure server_config(const std::vector<Endpoint>& p, const std::string& file) {
    const Json nets = {"198.18.241.1/32", "fd00:241::/126"};
    Json clients = Json::array();
    for (unsigned i = 1; i < p.size(); ++i) clients.push_back(client_entry(p[i], i, i == 3 ? Json{"fd00:241::/126"} : nets));
    return parse_config(Json{{"address_server", {{"address", p[0].str()}, {"bind_address", p[0].str()},
        {"state_file", file}, {"reclaim_after", 1}, {"networks", nets}, {"clients", clients}}}}.dump());
}
Configure client_config(const std::vector<Endpoint>& p, unsigned id, const Json& nets = Json{"198.18.241.1/32", "fd00:241::/126"}) {
    return parse_config(Json{{"address", p[id].str()}, {"address_clients", Json::array({client_entry(p[0], id, nets)})}}.dump());
}
const std::string admission_key = "test-only-shared-admission-key";
Configure shared_server_config(const std::vector<Endpoint>& p, const std::string& file) {
    auto doc = Json::parse(serialize_config(server_config(p, file)));
    doc["address_server"].erase("clients");
    doc["address_server"]["shared_key"] = admission_key;
    doc["address_server"]["networks"] = {"198.18.242.0/24", "fd00:242::/120"};
    return parse_config(doc.dump());
}
Configure shared_client_config(const std::vector<Endpoint>& p, unsigned id,
                               const Json& nets = Json{"198.18.242.0/24", "fd00:242::/120"}) {
    auto config = client_config(p, id, nets); config.address_clients[0].shared_key = admission_key; return config;
}
AddressService::Options options() {
    AddressService::Options o; o.tick_ms = 20; o.heartbeat_ms = 250; o.failure_timeout_ms = 3000;
    o.handshake_timeout_ms = 3000; o.reconnect_ms = 100; o.proof_lifetime_ms = 4000; return o;
}
struct Observed {
    std::map<Network, AddressService::Grant> grants; unsigned losses = 0, updates = 0;
    void update(const Network& n, const AddressService::Grant* g) { if (g) { grants[n] = *g; ++updates; } else { grants.erase(n); ++losses; } }
};
AddressService::Callback watch(Observed& o) { return [&o](const Network& n, const AddressService::Grant* g) { o.update(n, g); }; }
void config_tests(const std::vector<Endpoint>& p, const std::string& file) {
    const auto server = server_config(p, file); const auto client = client_config(p, 1);
    CHECK(server.networks.empty()); CHECK(server.listen.address.port == 0); CHECK(server.address_server.enabled);
    CHECK(server.address_server.clients.size() == p.size() - 1); CHECK(server.address_server.reclaim_after == 1);
    CHECK(client.networks.size() == 2); CHECK(client.listen.networks.size() == 2);
    for (const auto& n : client.networks) { CHECK(n.tunnel_ip.unspecified()); CHECK(n.tunnel_ip.family == n.tunnel.address.family); CHECK(n.allocation_server == p[0]); }
    const auto serialized = serialize_config(client); const auto doc = Json::parse(serialized);
    CHECK(!doc.count("networks")); CHECK(doc.at("address_clients").size() == 1);
    CHECK(serialize_config(parse_config(serialized)) == serialized);
    CHECK(serialize_config(parse_config(serialize_config(server))) == serialize_config(server));
    auto mixed = doc; mixed["networks"] = {"10.190.1.1/24"}; mixed["listen"] = {{"networks", Json::array()}};
    mixed["peers"] = Json::array({{{"address", p[2].str()}, {"shared_key", "overlay-secret"}, {"networks", {"fd00:241::/126"}}}});
    auto parsed = parse_config(mixed.dump()); CHECK(parsed.networks.size() == 3); CHECK(parsed.listen.networks.empty());
    CHECK(parsed.peers[0].networks[0].allocation_server == p[0]); CHECK(parse_config(serialize_config(parsed)).listen.networks.empty());
    auto bad = mixed; bad["networks"] = {"198.18.241.1/32"}; rejects([&] { parse_config(bad.dump()); });
    bad = mixed; bad["networks"] = {"198.18.241.2/24"}; rejects([&] { parse_config(bad.dump()); });
    bad = mixed; bad["peers"][0].erase("networks"); rejects([&] { parse_config(bad.dump()); });
    bad = doc; bad["address_clients"].push_back(client_entry(p[2], 2, {"198.18.241.1/32"})); rejects([&] { parse_config(bad.dump()); });
    bad = doc; bad["address_clients"][0]["networks"] = {"fd00:241::1/126"}; rejects([&] { parse_config(bad.dump()); });
    bad = doc; bad["address_clients"][0]["networks"] = Json::array(); rejects([&] { parse_config(bad.dump()); });
    bad = doc; bad["address_clients"][0]["enabled"] = true; rejects([&] { parse_config(bad.dump()); });
    bad = Json::parse(serialize_config(server)); bad["address_server"]["clients"][1]["shared_key"] = bad["address_server"]["clients"][0]["shared_key"];
    rejects([&] { parse_config(bad.dump()); });
    bad = Json::parse(serialize_config(server)); bad["address_server"]["clients"][0]["networks"] = {"10.12.0.0/16"}; rejects([&] { parse_config(bad.dump()); });
    bad = Json::parse(serialize_config(server)); bad["address_server"]["reclaim_after"] = 0; rejects([&] { parse_config(bad.dump()); });
    bad = Json::parse(serialize_config(server)); bad["address_server"]["state_file"] = "relative.json";
    CHECK(parse_config(bad.dump()).address_server.state_file == "relative.json");
    bad["address"] = p[0].str(); bad["networks"] = {"10.190.1.1/24"}; rejects([&] { parse_config(bad.dump()); });
    bad["address"] = p[1].str(); CHECK(parse_config(bad.dump()).address_server.enabled);
    bad["networks"] = {"198.18.241.2/24"}; rejects([&] { parse_config(bad.dump()); });
    bad.erase("networks");
    bad["address_clients"] = Json::array({client_entry(p[0], 1, {"198.18.241.1/32", "fd00:241::/126"})});
    const auto own_server = parse_config(bad.dump()); CHECK(own_server.networks.size() == 2);
    CHECK(own_server.address_clients[0].address == own_server.address_server.address);
    CHECK(parse_config(serialize_config(own_server)).networks.size() == 2);
    for (const auto& invalid_pool : {"0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::/128", "ff00::/8"}) {
        bad = Json::parse(serialize_config(server)); bad["address_server"]["networks"] = {invalid_pool}; bad["address_server"]["clients"] = Json::array();
        rejects([&] { parse_config(bad.dump()); });
    }
    for (const auto& valid_pool : {"0.0.0.0/7", "0.0.0.0/0", "::/127", "::/0"}) {
        bad = Json::parse(serialize_config(server)); bad["address_server"]["networks"] = {valid_pool}; bad["address_server"]["clients"] = Json::array();
        CHECK(parse_config(bad.dump()).address_server.networks.size() == 1);
    }
    const auto shared = shared_server_config(p, file);
    CHECK(shared.address_server.clients.empty()); CHECK(shared.address_server.shared_key == admission_key);
    const auto normalized_shared = serialize_config(shared); const auto shared_doc = Json::parse(normalized_shared);
    CHECK(!shared_doc["address_server"].count("clients")); CHECK(shared_doc["address_server"]["shared_key"] == admission_key);
    CHECK(serialize_config(parse_config(normalized_shared)) == normalized_shared);
    CHECK(!Json::parse(serialize_config(server))["address_server"].count("shared_key"));
    bad = shared_doc; bad["address_server"]["clients"] = Json::array(); rejects([&] { parse_config(bad.dump()); });
    bad = Json::parse(serialize_config(server)); bad["address_server"]["shared_key"] = admission_key; rejects([&] { parse_config(bad.dump()); });
    for (const auto& invalid : Json::array({"", nullptr, 7})) {
        bad = shared_doc; bad["address_server"]["shared_key"] = invalid; rejects([&] { parse_config(bad.dump()); });
    }
    bad = shared_doc; bad["address_server"].erase("shared_key"); rejects([&] { parse_config(bad.dump()); });
    bad["address_server"]["clients"] = Json::array();
    CHECK(parse_config(bad.dump()).address_server.shared_key.empty());
    CHECK(Json::parse(serialize_config(parse_config(bad.dump())))["address_server"]["clients"].empty());
    auto ambiguous = shared; ambiguous.address_server.clients = server.address_server.clients;
    rejects([&] { serialize_config(ambiguous); });
}
void network_tests(const std::vector<Endpoint>& p, const std::string& file) {
    std::cerr << "allocation: TLS authentication and independent pools\n";
    clean(file); EventLoop loop; auto opts = options();
    const auto cfg = server_config(p, file); AddressService server(loop, cfg, {}, opts); server.start();
    AddressService locked(loop, cfg, {}, opts); rejects([&] { locked.start(); });
    Observed a, b, denied, wrong, duplicate;
    AddressService ca(loop, client_config(p, 1), watch(a), opts); ca.start(); until(loop, [&] { return a.grants.size() == 2; });
    AddressService cb(loop, client_config(p, 2), watch(b), opts); cb.start(); until(loop, [&] { return b.grants.size() == 1; });
    const auto v4 = Network::parse("198.18.241.1/32"), v6 = Network::parse("fd00:241::/126");
    CHECK(a.grants.at(v4).ip.str() == "198.18.241.1"); CHECK(b.grants.count(v6) == 1);
    CHECK(a.grants.at(v6).ip != b.grants.at(v6).ip); CHECK(cb.status()["clients"][0]["errors"].size() == 1);
    CHECK(cb.status()["clients"][0]["errors"][0]["network"] == v4.str());
    IpAddress verified; CHECK(ca.verify_grant(p[2], v6, b.grants.at(v6).proof, &verified)); CHECK(verified == b.grants.at(v6).ip);
    CHECK(!cb.verify_grant(p[1], v4, a.grants.at(v4).proof)); // No local authorization for an exhausted pool.
    auto tampered = b.grants.at(v6).proof; tampered["body"]["ip"] = "fd00:241::3"; CHECK(!ca.verify_grant(p[2], v6, tampered));
    tampered = b.grants.at(v6).proof; tampered["body"]["expires_at"] = 0; CHECK(!ca.verify_grant(p[2], v6, tampered));
    CHECK(!ca.verify_grant(p[1], v6, b.grants.at(v6).proof)); CHECK(!ca.verify_grant(p[2], v4, b.grants.at(v6).proof));
    AddressService cd(loop, client_config(p, 3), watch(denied), opts); cd.start();
    auto wrong_cfg = client_config(p, 4); wrong_cfg.address_clients[0].shared_key = "wrong-key";
    AddressService cw(loop, wrong_cfg, watch(wrong), opts); cw.start();
    AddressService duplicate_a(loop, client_config(p, 1), watch(duplicate), opts); duplicate_a.start();
    spin(loop, 450); CHECK(denied.grants.empty()); CHECK(wrong.grants.empty()); CHECK(duplicate.grants.empty()); CHECK(a.grants.size() == 2);
    CHECK(server.status()["server"]["leases"].size() == 3); cd.stop(); cw.stop(); duplicate_a.stop();
    const auto address_a = a.grants.at(v6).ip, address_b = b.grants.at(v6).ip; const auto loss = a.losses;
    std::cerr << "allocation: reset/reconnect and proof renewal\n";
    ca.reset_links(); CHECK(a.grants.empty()); CHECK(a.losses == loss + 2);
    until(loop, [&] { return a.grants.size() == 2; }); CHECK(a.grants.at(v6).ip == address_a);
    const auto old_proof = b.grants.at(v6).proof; const auto renewals = a.updates;
    until(loop, [&] { return a.updates > renewals; }); CHECK(a.grants.at(v6).ip == address_a);
    std::cerr << "allocation: restart, persisted binding, authority rotation\n";
    server.stop(); until(loop, [&] { return a.grants.empty() && b.grants.empty(); });
    CHECK(!ca.verify_grant(p[2], v6, old_proof));
    server.start(); until(loop, [&] { return a.grants.size() == 2 && b.grants.size() == 1; });
    CHECK(a.grants.at(v6).ip == address_a); CHECK(b.grants.at(v6).ip == address_b);
    CHECK(!ca.verify_grant(p[2], v6, old_proof)); CHECK(ca.verify_grant(p[2], v6, b.grants.at(v6).proof));
    std::cerr << "allocation: reclaim waits for issued proofs\n";
    ca.stop(); until(loop, [&] { const auto status = server.status(); for (const auto& l : status["server"]["leases"]) if (l["node"] == p[1].str() && l["online"] == true) return false; return true; });
    const auto persisted = Json::parse(read_file(file));
    for (const auto& lease : persisted["leases"]) if (lease["node"] == p[1].str()) CHECK(lease["proof_until"].get<std::uint64_t>() > lease["offline_at"].get<std::uint64_t>() + 1000);
    spin(loop, 1300); CHECK(b.grants.count(v4) == 0); // Configured reclaim delay elapsed, proof guard has not.
    try { until(loop, [&] { return b.grants.count(v4) == 1; }, 12000); }
    catch (...) { std::cerr << server.status().dump(2) << '\n' << cb.status().dump(2) << '\n'; throw; }
    CHECK(b.grants.at(v4).ip.str() == "198.18.241.1");
    cb.stop(); server.stop(); clean(file);
}
void storage_tests(const std::vector<Endpoint>& p, const std::string& file) {
    std::cerr << "allocation: corrupt database and fail-closed writes\n";
    clean(file); EventLoop loop; const auto cfg = server_config(p, file); auto opts = options();
    write_file(file, "{\"version\":1,\"version\":1}"); { AddressService s(loop, cfg, {}, opts); rejects([&] { s.start(); }); } clean(file);
    write_file(file, std::string(100, '[') + "0" + std::string(100, ']')); { AddressService s(loop, cfg, {}, opts); rejects([&] { s.start(); }); } clean(file);
    Json value = {{"version", 1}, {"server", p[0].str()}, {"leases", Json::array({{{"network", "198.18.241.1/32"}, {"node", p[1].str()}, {"ip", "198.18.241.2"}, {"offline_at", 1}, {"proof_until", 1}}})}};
    write_file(file, value.dump()); { AddressService s(loop, cfg, {}, opts); rejects([&] { s.start(); }); } clean(file);
    value["leases"][0]["ip"] = "198.18.241.1";
    value["leases"][0]["offline_at"] = std::numeric_limits<std::uint64_t>::max();
    write_file(file, value.dump()); { AddressService s(loop, cfg, {}, opts); rejects([&] { s.start(); }); } clean(file);
    value["leases"][0]["offline_at"] = 1;
    value["leases"][0]["network"] = "198.18.241.1/24"; // Host bits must not silently change a persisted pool.
    write_file(file, value.dump()); { AddressService s(loop, cfg, {}, opts); rejects([&] { s.start(); }); } clean(file);
    AddressService server(loop, cfg, {}, opts); Observed received;
    AddressService client(loop, client_config(p, 1), watch(received), opts); server.start(); client.start();
    until(loop, [&] { return received.grants.size() == 2; });
#ifdef _WIN32
    CHECK(_mkdir((file + ".tmp").c_str()) == 0);
#else
    CHECK(mkdir((file + ".tmp").c_str(), 0700) == 0);
#endif
    until(loop, [&] { return server.status()["server"]["running"] == false && received.grants.empty(); });
    CHECK(!server.status()["server"]["error"].get<std::string>().empty());
    client.stop(); server.stop();
#ifdef _WIN32
    CHECK(_rmdir((file + ".tmp").c_str()) == 0);
#else
    CHECK(rmdir((file + ".tmp").c_str()) == 0);
#endif
    clean(file);
}
void broad_pool_test(const std::vector<Endpoint>& p, const std::string& file) {
    std::cerr << "allocation: skip non-unicast IPv4 block in a broad pool\n";
    clean(file); EventLoop loop; auto opts = options(); const Json pools = {"0.0.0.0/7"};
    auto doc = Json::parse(serialize_config(server_config(p, file)));
    doc["address_server"]["networks"] = pools;
    doc["address_server"]["clients"] = Json::array({client_entry(p[1], 1, pools)});
    AddressService server(loop, parse_config(doc.dump()), {}, opts); Observed received;
    AddressService client(loop, client_config(p, 1, pools), watch(received), opts);
    server.start(); client.start(); until(loop, [&] { return received.grants.size() == 1; });
    CHECK(received.grants.begin()->second.ip.str() == "1.0.0.0");
    client.stop(); server.stop(); clean(file);
}
void shared_admission_tests(const std::string& file) {
    std::cerr << "allocation: shared admission, dynamic identities, and persisted bindings\n";
    clean(file); EventLoop loop; const auto p = ports(20);
    auto opts = options(); opts.heartbeat_ms = 1000; opts.failure_timeout_ms = 5000; opts.handshake_timeout_ms = 5000; opts.proof_lifetime_ms = 10000;
    const auto server_config = shared_server_config(p, file);
    CHECK(server_config.address_server.clients.empty());
    AddressService server(loop, server_config, {}, opts); server.start();
    std::vector<Observed> observed(18);
    std::vector<std::unique_ptr<AddressService>> members;
    for (unsigned i = 1; i <= 2; ++i) {
        members.emplace_back(new AddressService(loop, shared_client_config(p, i), watch(observed[i]), opts)); members.back()->start();
    }
    until(loop, [&] { return observed[1].grants.size() == 2 && observed[2].grants.size() == 2; });
    const auto v4 = Network::parse("198.18.242.0/24"), v6 = Network::parse("fd00:242::/120");
    CHECK(observed[1].grants.at(v4).ip != observed[2].grants.at(v4).ip);
    CHECK(observed[1].grants.at(v6).ip != observed[2].grants.at(v6).ip);
    CHECK(members[0]->verify_grant(p[2], v4, observed[2].grants.at(v4).proof));
    Observed wrong, denied, duplicate;
    auto wrong_config = shared_client_config(p, 3); wrong_config.address_clients[0].shared_key = "wrong-shared-key";
    AddressService wrong_member(loop, wrong_config, watch(wrong), opts);
    AddressService unknown_pool(loop, shared_client_config(p, 4, {"198.18.242.0/24", "10.221.0.0/16"}), watch(denied), opts);
    AddressService duplicate_member(loop, shared_client_config(p, 1), watch(duplicate), opts);
    wrong_member.start(); unknown_pool.start(); duplicate_member.start();
    until(loop, [&] { return !wrong_member.status()["clients"][0]["error"].get<std::string>().empty() &&
        !unknown_pool.status()["clients"][0]["error"].get<std::string>().empty() &&
        !duplicate_member.status()["clients"][0]["error"].get<std::string>().empty(); });
    CHECK(wrong.grants.empty()); CHECK(denied.grants.empty()); CHECK(duplicate.grants.empty());
    CHECK(observed[1].losses == 0 && observed[1].grants.size() == 2);
    CHECK(server.status()["server"]["leases"].size() == 4);
    wrong_member.stop(); unknown_pool.stop(); duplicate_member.stop();
    // Shared admission must not inherit the old empty-ACL limit of 16 sockets.
    for (unsigned i = 3; i <= 17; ++i) {
        members.emplace_back(new AddressService(loop, shared_client_config(p, i), watch(observed[i]), opts)); members.back()->start();
    }
    auto all_members = [&](const char* phase) {
        try { until(loop, [&] { for (unsigned i = 1; i <= 17; ++i) if (observed[i].grants.size() != 2) return false; return true; }, 15000); }
        catch (...) {
            std::cerr << "shared admission " << phase << ": " << server.status().dump() << '\n';
            for (unsigned i = 1; i <= 17; ++i) std::cerr << "member " << i << " grants=" << observed[i].grants.size()
                << " losses=" << observed[i].losses << " updates=" << observed[i].updates << " " << members[i - 1]->status().dump() << '\n';
            throw;
        }
    };
    all_members("initial admission");
    CHECK(server.status()["server"]["leases"].size() == 34);
    std::vector<std::map<Network, AddressService::Grant>> original;
    for (unsigned i = 1; i <= 17; ++i) original.push_back(observed[i].grants);
    server.stop(); until(loop, [&] { for (unsigned i = 1; i <= 17; ++i) if (!observed[i].grants.empty()) return false; return true; });
    server.start(); all_members("after server restart");
    for (unsigned i = 1; i <= 17; ++i) {
        CHECK(observed[i].grants.at(v4).ip == original[i - 1].at(v4).ip);
        CHECK(observed[i].grants.at(v6).ip == original[i - 1].at(v6).ip);
    }
    CHECK(!members[0]->verify_grant(p[2], v4, original[1].at(v4).proof));
    CHECK(members[0]->verify_grant(p[2], v4, observed[2].grants.at(v4).proof));
    for (auto& member : members) member->stop();
    server.stop(); clean(file);
    // A removed pool/node is still reserved until old grants expire. Removing
    // an ACL entry or switching auth modes must not discard those reservations.
    const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    Json retained = {{"version", 1}, {"server", p[0].str()}, {"leases", Json::array({
        {{"network", "10.222.0.0/24"}, {"node", "192.0.2.99:45000"}, {"ip", "10.222.0.1"}, {"offline_at", now}, {"proof_until", now + 60000}}
    })}};
    write_file(file, retained.dump());
    auto migrated_config = server_config;
    migrated_config.address_server.networks = {Network::parse("10.222.0.0/25")};
    AddressService retained_server(loop, migrated_config, {}, opts); retained_server.start();
    CHECK(retained_server.status()["server"]["leases"].size() == 1);
    CHECK(retained_server.status()["server"]["leases"][0]["node"] == "192.0.2.99:45000");
    Observed migrated;
    AddressService migrated_client(loop, shared_client_config(p, 1, {"10.222.0.0/25"}), watch(migrated), opts);
    migrated_client.start(); until(loop, [&] { return migrated.grants.size() == 1; });
    CHECK(migrated.grants.begin()->second.ip.str() == "10.222.0.2");
    migrated_client.stop();
    retained_server.stop(); clean(file);
    auto duplicate_lease = retained["leases"][0]; duplicate_lease["node"] = p[1].str();
    retained["leases"].push_back(duplicate_lease);
    write_file(file, retained.dump());
    { AddressService invalid(loop, server_config, {}, opts); rejects([&] { invalid.start(); }); }
    clean(file);
    retained["leases"].erase(1); retained["leases"][0]["node"] = "224.0.0.1:45000";
    write_file(file, retained.dump());
    { AddressService invalid(loop, server_config, {}, opts); rejects([&] { invalid.start(); }); }
    clean(file);
}
}
int main(int argc, char** argv) {
    try {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        SocketSystem sockets; const auto p = ports(5); const std::string file = argc > 1 ? argv[1] : "address-service-test-state";
        config_tests(p, file); network_tests(p, file); storage_tests(p, file); broad_pool_test(p, file); shared_admission_tests(file);
        std::cout << "Passed " << checks << " address service checks\n"; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
