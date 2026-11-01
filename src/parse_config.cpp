#include "parse_config.h"
#include "protocol.h"
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

Config g_config;
namespace {
using json = nlohmann::json;
void keys(const json& value, const std::set<std::string>& allowed, const std::string& path) {
    if (!value.is_object()) throw config_error(path + ": expected object");
    for (auto it = value.begin(); it != value.end(); ++it)
        if (!allowed.count(it.key())) throw config_error(path + ": unknown field '" + it.key() + "'");
}
const json& field(const json& value, const char* name, const std::string& path) {
    auto it = value.find(name);
    if (it == value.end()) throw config_error(path + ": missing '" + name + "'");
    return *it;
}
std::string string_value(const json& value, const std::string& path) {
    if (!value.is_string() || value.get<std::string>().empty()) throw config_error(path + ": expected nonempty string");
    return value.get<std::string>();
}
unsigned number(const json& object, const char* name, unsigned fallback, unsigned minimum, unsigned maximum) {
    const auto it = object.find(name);
    if (it == object.end()) return fallback;
    if (!it->is_number_integer() || *it < minimum || *it > maximum)
        throw config_error(std::string(name) + ": expected integer in " + std::to_string(minimum) + ".." + std::to_string(maximum));
    return it->get<unsigned>();
}
Endpoint endpoint(const json& value, const std::string& path, bool allow_wildcard) {
    try {
        const auto e = Endpoint::parse(string_value(value, path));
        if (!e.ip.unicast() && !(allow_wildcard && e.ip.unspecified()))
            throw config_error(path + ": expected unicast address");
        return e;
    } catch (const std::invalid_argument& e) { throw config_error(path + ": " + e.what()); }
}
void add_local(const NetworkConfig& n, const std::string& path, std::map<Network, IpAddress>& local) {
    if (!n.tunnel.usable_host(n.tunnel_ip)) throw config_error(path + ": tunnel_ip is not a usable address in tunnel");
    if (!local.count(n.tunnel) && local.size() >= 64) throw config_error("at most 64 distinct virtual networks are supported");
    for (const auto& old : local) {
        if (old.first == n.tunnel) {
            if (old.second != n.tunnel_ip) throw config_error(path + ": inconsistent local tunnel_ip");
        } else if (old.first.overlaps(n.tunnel)) throw config_error(path + ": overlapping virtual networks");
    }
    local[n.tunnel] = n.tunnel_ip;
}
std::vector<NetworkConfig> legacy_networks(const json& value, const std::string& path,
                                    std::map<Network, IpAddress>& local) {
    if (!value.is_array()) throw config_error(path + ": expected array");
    if (value.size() > 64) throw config_error(path + ": at most 64 networks are supported");
    std::vector<NetworkConfig> result;
    std::set<Network> seen;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto p = path + "[" + std::to_string(i) + "]";
        keys(value[i], {"tunnel", "tunnel_ip"}, p);
        NetworkConfig n;
        try {
            n.tunnel = Network::parse(string_value(field(value[i], "tunnel", p), p + ".tunnel"));
            n.tunnel_ip = IpAddress::parse(string_value(field(value[i], "tunnel_ip", p), p + ".tunnel_ip"));
        } catch (const std::invalid_argument& e) { throw config_error(p + ": " + e.what()); }
        if (!seen.insert(n.tunnel).second) throw config_error(p + ": duplicate normalized network");
        add_local(n, p, local);
        result.push_back(n);
    }
    return result;
}
std::vector<NetworkConfig> local_networks(const json& value, std::map<Network, IpAddress>& local) {
    if (!value.is_array()) throw config_error("networks: expected host CIDR array");
    if (value.empty() || value.size() > 64) throw config_error("networks: expected 1..64 local networks");
    std::vector<NetworkConfig> result;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto path = "networks[" + std::to_string(i) + "]";
        const auto cidr = string_value(value[i], path);
        NetworkConfig n;
        try {
            n.tunnel = Network::parse(cidr);
            n.tunnel_ip = IpAddress::parse(cidr.substr(0, cidr.find('/')));
        } catch (const std::invalid_argument& e) { throw config_error(path + ": " + e.what()); }
        if (local.count(n.tunnel)) throw config_error(path + ": duplicate normalized network");
        add_local(n, path, local);
        result.push_back(n);
    }
    return result;
}
std::vector<NetworkConfig> network_refs(const json& value, const std::string& path,
                                      const std::map<Network, IpAddress>& local) {
    if (!value.is_array()) throw config_error(path + ": expected subnet CIDR array");
    if (value.size() > 64) throw config_error(path + ": at most 64 networks are supported");
    std::vector<NetworkConfig> result;
    std::set<Network> seen;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto p = path + "[" + std::to_string(i) + "]";
        const auto cidr = string_value(value[i], p);
        NetworkConfig n;
        try {
            n.tunnel = Network::parse(cidr);
            if (!(IpAddress::parse(cidr.substr(0, cidr.find('/'))) == n.tunnel.address))
                throw config_error(p + ": use a subnet CIDR without host bits");
        } catch (const std::invalid_argument& e) { throw config_error(p + ": " + e.what()); }
        const auto found = local.find(n.tunnel);
        if (found == local.end()) throw config_error(p + ": subnet is not declared in networks");
        if (!seen.insert(n.tunnel).second) throw config_error(p + ": duplicate normalized network");
        n.tunnel_ip = found->second;
        result.push_back(n);
    }
    return result;
}
json serialized_refs(const std::vector<NetworkConfig>& networks, const std::map<Network, IpAddress>& local) {
    std::set<Network> sorted;
    for (const auto& n : networks) {
        const auto found = local.find(n.tunnel);
        if (found == local.end() || !(found->second == n.tunnel_ip))
            throw config_error("cannot serialize an undeclared or inconsistent network authorization");
        if (!sorted.insert(n.tunnel).second) throw config_error("cannot serialize duplicate network authorizations");
    }
    auto result = json::array();
    for (const auto& network : sorted) result.push_back(network.str());
    return result;
}
std::vector<Network> service_networks(const json& value, const std::string& path) {
    if (!value.is_array() || value.empty() || value.size() > 64)
        throw config_error(path + ": expected 1..64 subnet CIDRs");
    std::vector<Network> result;
    for (const auto& entry : value) {
        const auto text = string_value(entry, path);
        Network n;
        try {
            n = Network::parse(text);
            if (!(IpAddress::parse(text.substr(0, text.find('/'))) == n.address))
                throw config_error(path + ": expected subnet CIDR without host bits");
        } catch (const std::invalid_argument& e) { throw config_error(path + ": " + e.what()); }
        auto first = n.address;
        // Skip the entire non-unicast IPv4 0/8 block without iterating hosts.
        if (first.family == 4 && first.bytes[0] == 0) { first.bytes.fill(0); first.bytes[0] = 1; }
        else if ((first.family == 4 && n.prefix < 31) || (first.family == 6 && n.prefix < 128))
            for (int i = first.family == 4 ? 3 : 15; i >= 0; --i) if (++first.bytes[static_cast<std::size_t>(i)]) break;
        if (!n.usable_host(first)) throw config_error(path + ": pool has no usable unicast addresses");
        for (const auto& old : result) if (old.overlaps(n)) throw config_error(path + ": duplicate or overlapping pools");
        result.push_back(n);
    }
    return result;
}
std::vector<AddressClientConfig> service_clients(const json& value, const std::string& path) {
    if (!value.is_array() || value.size() > 256) throw config_error(path + ": expected at most 256 entries");
    std::vector<AddressClientConfig> result; std::set<Endpoint> seen;
    for (const auto& entry : value) {
        keys(entry, {"address", "shared_key", "networks"}, path);
        AddressClientConfig c;
        c.address = endpoint(field(entry, "address", path), path + ".address", false);
        c.shared_key = string_value(field(entry, "shared_key", path), path + ".shared_key");
        c.networks = service_networks(field(entry, "networks", path), path + ".networks");
        if (!seen.insert(c.address).second) throw config_error(path + ": duplicate address");
        result.push_back(c);
    }
    return result;
}
AddressServerConfig service_server(const json& value) {
    const std::string p = "address_server";
    keys(value, {"address", "bind_address", "state_file", "reclaim_after", "networks", "clients", "shared_key"}, p);
    AddressServerConfig s; s.enabled = true;
    s.address = endpoint(field(value, "address", p), p + ".address", false);
    s.bind_address = s.address; s.bind_address.ip.bytes.fill(0);
    if (value.count("bind_address")) s.bind_address = endpoint(value["bind_address"], p + ".bind_address", true);
    if (s.bind_address.ip.family != s.address.ip.family) throw config_error(p + ": bind address family mismatch");
    if (value.count("state_file")) s.state_file = string_value(value["state_file"], p + ".state_file");
    if (s.state_file.find('\0') != std::string::npos) throw config_error(p + ": NUL in state_file");
    s.reclaim_after = number(value, "reclaim_after", 86400, 1, 31536000);
    s.networks = service_networks(field(value, "networks", p), p + ".networks");
    if (value.count("shared_key")) {
        if (value.count("clients")) throw config_error(p + ": shared_key and clients are mutually exclusive");
        s.shared_key = string_value(value["shared_key"], p + ".shared_key");
    } else s.clients = service_clients(field(value, "clients", p), p + ".clients");
    std::set<std::string> secrets;
    for (const auto& c : s.clients) {
        if (!secrets.insert(c.shared_key).second) throw config_error(p + ": each client requires a different shared_key");
        for (const auto& n : c.networks)
            if (std::find(s.networks.begin(), s.networks.end(), n) == s.networks.end())
                throw config_error(p + ": client references an undeclared pool");
    }
    return s;
}
json service_client_json(const AddressClientConfig& c) {
    json value = {{"address", c.address.str()}, {"shared_key", c.shared_key}, {"networks", json::array()}};
    for (const auto& n : c.networks) value["networks"].push_back(n.str());
    return value;
}
std::vector<AdvertisedRoute> advertised_routes(const json& value, const std::map<Network, IpAddress>& local) {
    if (!value.is_array() || value.size() > 64) throw config_error("advertise_routes: expected at most 64 routes");
    std::vector<AdvertisedRoute> result;
    for (const auto& entry : value) {
        keys(entry, {"tunnel", "prefix", "snat"}, "advertise_routes");
        AdvertisedRoute r;
        try {
            const auto tunnel = string_value(field(entry, "tunnel", "advertise_routes"), "advertise_routes.tunnel");
            const auto prefix = string_value(field(entry, "prefix", "advertise_routes"), "advertise_routes.prefix");
            r.tunnel = Network::parse(tunnel); r.prefix = Network::parse(prefix);
            if (!(IpAddress::parse(tunnel.substr(0, tunnel.find('/'))) == r.tunnel.address) ||
                !(IpAddress::parse(prefix.substr(0, prefix.find('/'))) == r.prefix.address))
                throw config_error("advertise_routes: use subnet CIDRs without host bits");
        } catch (const std::invalid_argument& e) { throw config_error(std::string("advertise_routes: ") + e.what()); }
        if (!local.count(r.tunnel)) throw config_error("advertise_routes.tunnel: undeclared local tunnel");
        if (r.tunnel.address.family != r.prefix.address.family || !valid_advertised_prefix(r.prefix))
            throw config_error("advertise_routes.prefix: expected a non-default unicast CIDR in the tunnel IP family");
        if (entry.count("snat")) {
            if (!entry["snat"].is_boolean()) throw config_error("advertise_routes.snat: expected boolean");
            r.snat = entry["snat"].get<bool>();
        }
        for (const auto& n : local) if (r.prefix.overlaps(n.first))
            throw config_error("advertise_routes.prefix: overlaps a local tunnel");
        for (const auto& old : result) if (r.prefix.overlaps(old.prefix))
            throw config_error("advertise_routes.prefix: duplicate or overlapping advertised prefixes");
        result.push_back(r);
    }
    return result;
}
RemoteDesktopConfig remote_desktop(const json& value, const std::map<Network, IpAddress>& local) {
    const std::string path = "remote_desktop";
    keys(value, {"enabled", "networks", "access", "unattended", "port", "device_name"}, path);
    RemoteDesktopConfig result; result.configured = true;
    for (const auto name : {"enabled", "unattended"}) if (value.count(name)) {
        if (!value[name].is_boolean()) throw config_error(path + "." + name + ": expected boolean");
        if (std::string(name) == "enabled") result.enabled = value[name].get<bool>();
        else result.unattended = value[name].get<bool>();
    }
    if (value.count("access")) {
        result.access = string_value(value["access"], path + ".access");
        if (result.access != "authorized_devices" && result.access != "all_tunnel_nodes")
            throw config_error(path + ".access: expected authorized_devices or all_tunnel_nodes");
    }
    result.port = number(value, "port", 47831, 1, 65535);
    if (value.count("device_name")) {
        if (!value["device_name"].is_string()) throw config_error(path + ".device_name: expected string");
        result.device_name = value["device_name"].get<std::string>();
        if (result.device_name.size() > 128 || std::any_of(result.device_name.begin(), result.device_name.end(),
                [](unsigned char ch) { return ch < 32 || ch == 127; }))
            throw config_error(path + ".device_name: expected at most 128 UTF-8 bytes without control characters");
    }
    if (value.count("networks")) {
        for (const auto& n : network_refs(value["networks"], path + ".networks", local)) result.networks.push_back(n.tunnel);
    } else if (local.size() == 1) result.networks.push_back(local.begin()->first);
    else if (result.enabled && local.size() > 1)
        throw config_error(path + ".networks: explicit selection required for multiple local networks");
    if (result.enabled && result.networks.empty()) throw config_error(path + ".networks: select at least one local network");
    return result;
}
}
bool valid_advertised_prefix(const Network& network) {
    const auto family = network.address.family;
    if ((family != 4 && family != 6) || !network.prefix || network.prefix > (family == 4 ? 32u : 128u)) return false;
    if (!network.contains(network.address) || !network.address.unicast()) return false;
    auto last = network.address;
    for (unsigned bit = network.prefix; bit < (family == 4 ? 32u : 128u); ++bit)
        last.bytes[bit / 8] |= static_cast<unsigned char>(1u << (7 - bit % 8));
    return last.unicast();
}
Configure parse_config(const std::string& text) {
    if (text.size() > 1024 * 1024) throw config_error("configuration exceeds 1 MiB");
    try {
        std::vector<std::set<std::string>> object_keys;
        const auto doc = json::parse(text, [&](int depth, json::parse_event_t event, json& value) {
            if (depth > 16) throw config_error("configuration nesting exceeds 16 levels");
            if (event == json::parse_event_t::object_start) object_keys.emplace_back();
            else if (event == json::parse_event_t::key && !object_keys.back().insert(value.get<std::string>()).second)
                throw config_error("duplicate JSON object key: " + value.get<std::string>());
            else if (event == json::parse_event_t::object_end) object_keys.pop_back();
            return true;
        });
        const std::string config_path = "configuration";
        const std::string listen_path = "listen";
        const bool only_server = doc.is_object() && doc.count("address_server") && !doc.count("address") && !doc.count("listen") && !doc.count("networks") && !doc.count("peers") && !doc.count("address_clients");
        const bool simplified = doc.is_object() && (doc.count("address") || doc.count("networks") || doc.count("address_clients") || only_server);
        keys(doc, simplified ? std::set<std::string>{"address", "networks", "tun_mtu", "transport_mtu", "thread_num", "listen", "peers", "address_server", "address_clients", "advertise_routes", "remote_desktop", "device_backend"} :
                              std::set<std::string>{"tun_mtu", "transport_mtu", "thread_num", "listen", "peers", "address_server", "advertise_routes", "remote_desktop", "device_backend"}, config_path);
        number(doc, "thread_num", 1, 1, 1);
        Configure result;
        result.tun_mtu = number(doc, "tun_mtu", 1280, 576, 65535);
        result.transport_mtu = number(doc, "transport_mtu", 1500, 576, 65535);
        if (doc.count("device_backend")) {
            result.device_backend = string_value(doc["device_backend"], "device_backend");
            if (result.device_backend != "tun" && result.device_backend != "kernel")
                throw config_error("device_backend: expected tun or kernel");
        }
        if (doc.count("address_server")) result.address_server = service_server(doc["address_server"]);
        if (only_server) {
            if (doc.count("advertise_routes")) result.advertise_routes = advertised_routes(doc["advertise_routes"], {});
            if (doc.count("remote_desktop")) result.remote_desktop = remote_desktop(doc["remote_desktop"], {});
            return result;
        }
        if (doc.count("address_clients")) result.address_clients = service_clients(doc["address_clients"], "address_clients");
        const auto empty_object = json::object();
        const auto& listen = simplified && !doc.count("listen") ? empty_object : field(doc, "listen", config_path);
        keys(listen, simplified ? std::set<std::string>{"enabled", "bind_address", "networks"} :
                                 std::set<std::string>{"enabled", "address", "bind_address", "networks"}, listen_path);
        const json default_enabled = true;
        const auto& enabled = simplified && !listen.count("enabled") ? default_enabled : field(listen, "enabled", listen_path);
        if (!enabled.is_boolean()) throw config_error("listen.enabled: expected boolean");
        result.listen.enabled = enabled.get<bool>();
        result.listen.address = simplified ? endpoint(field(doc, "address", config_path), "address", false) :
                                             endpoint(field(listen, "address", listen_path), "listen.address", false);
        result.listen.bind_address = result.listen.address;
        result.listen.bind_address.ip.bytes.fill(0);
        if (listen.count("bind_address"))
            result.listen.bind_address = endpoint(listen["bind_address"], "listen.bind_address", true);
        const auto family = result.listen.address.ip.family;
        if (result.listen.bind_address.ip.family != family) throw config_error("listen.bind_address: address family differs from advertised address");
        std::map<Network, IpAddress> local;
        std::map<Network, Endpoint> managed;
        if (simplified) {
            if (doc.count("networks") && (!doc["networks"].is_array() || !doc["networks"].empty())) local_networks(doc["networks"], local);
            else if (result.address_clients.empty()) throw config_error("networks: at least one static or managed network is required");
            for (const auto& c : result.address_clients) for (const auto& n : c.networks) {
                for (const auto& old : local) if (old.first.overlaps(n)) throw config_error("address_clients: duplicate or overlapping static/managed network");
                if (local.size() >= 64) throw config_error("at most 64 distinct virtual networks are supported");
                IpAddress ip; ip.family = n.address.family; local[n] = ip; managed[n] = c.address;
            }
            std::vector<NetworkConfig> all;
            for (const auto& item : local) { NetworkConfig n; n.tunnel = item.first; n.tunnel_ip = item.second; all.push_back(n); }
            result.listen.networks = listen.count("networks") ? network_refs(listen["networks"], "listen.networks", local) : all;
        } else result.listen.networks = legacy_networks(field(listen, "networks", listen_path), "listen.networks", local);
        const auto empty_array = json::array();
        const auto& peers = simplified && !doc.count("peers") ? empty_array : field(doc, "peers", config_path);
        if (!peers.is_array()) throw config_error("peers: expected array");
        if (peers.size() > 256) throw config_error("peers: at most 256 peers are supported");
        std::set<Endpoint> endpoints;
        for (std::size_t i = 0; i < peers.size(); ++i) {
            const auto p = "peers[" + std::to_string(i) + "]";
            keys(peers[i], {"address", "shared_key", "networks", "transport"}, p);
            PeerConfig peer;
            peer.address = endpoint(field(peers[i], "address", p), p + ".address", false);
            if (peer.address == result.listen.address) throw config_error(p + ": peer is the local node");
            if (peer.address.ip.family != family) throw config_error(p + ": first transport version requires one outer IP family");
            if (!endpoints.insert(peer.address).second) throw config_error(p + ": duplicate peer");
            peer.shared_key = string_value(field(peers[i], "shared_key", p), p + ".shared_key");
            if (peers[i].count("transport")) {
                peer.transport = string_value(peers[i]["transport"], p + ".transport");
                if (peer.transport != "udp" && peer.transport != "tcp")
                    throw config_error(p + ".transport: expected udp or tcp");
            }
            if (!simplified) peer.networks = legacy_networks(field(peers[i], "networks", p), p + ".networks", local);
            else if (peers[i].count("networks")) peer.networks = network_refs(peers[i]["networks"], p + ".networks", local);
            else if (local.size() == 1) {
                NetworkConfig n; n.tunnel = local.begin()->first; n.tunnel_ip = local.begin()->second;
                peer.networks.push_back(n);
            } else throw config_error(p + ": networks must be explicit when multiple local networks are configured");
            if (peer.networks.empty()) throw config_error(p + ": at least one network is required");
            result.peers.push_back(std::move(peer));
        }
        if (local.empty()) throw config_error("configuration: at least one virtual network is required");
        if (doc.count("advertise_routes")) result.advertise_routes = advertised_routes(doc["advertise_routes"], local);
        if (doc.count("remote_desktop")) result.remote_desktop = remote_desktop(doc["remote_desktop"], local);
        if (result.tun_mtu > protocol::maximum_tun_mtu(result.transport_mtu, family))
            throw config_error("tun_mtu: exceeds transport_mtu after IP/UDP, forwarding and two AEAD envelopes (maximum " +
                std::to_string(protocol::maximum_tun_mtu(result.transport_mtu, family)) + ")");
        for (const auto& item : local) {
            if (result.address_server.enabled && !managed.count(item.first))
                for (const auto& pool : result.address_server.networks) if (pool.overlaps(item.first))
                    throw config_error("address_server: a local static network overlaps an allocation pool; join that pool through address_clients");
            if (item.first.address.family == 6 && result.tun_mtu < 1280)
                throw config_error("tun_mtu: inner IPv6 requires at least 1280");
            NetworkConfig n; n.tunnel = item.first; n.tunnel_ip = item.second;
            if (managed.count(n.tunnel)) n.allocation_server = managed.at(n.tunnel);
            result.networks.push_back(n);
        }
        for (auto& n : result.listen.networks) if (managed.count(n.tunnel)) n.allocation_server = managed.at(n.tunnel);
        for (auto& p : result.peers) for (auto& n : p.networks) if (managed.count(n.tunnel)) n.allocation_server = managed.at(n.tunnel);
        if (result.address_server.enabled && result.address_server.bind_address.port == result.listen.bind_address.port &&
            result.address_server.bind_address.ip.family == result.listen.bind_address.ip.family && result.listen.enabled &&
            (result.address_server.bind_address.ip.unspecified() || result.listen.bind_address.ip.unspecified() || result.address_server.bind_address.ip == result.listen.bind_address.ip))
            throw config_error("address_server: listener conflicts with the overlay TCP bind address");
        return result;
    } catch (const json::parse_error& e) {
        // The original parser message can contain configuration fragments/PSKs.
        throw config_error("invalid JSON near byte " + std::to_string(e.byte));
    } catch (const json::exception& e) { throw config_error(std::string("invalid JSON configuration: ") + e.what()); }
}
Configure parse_config_file(const std::string& path) {
    std::ifstream input(path.c_str(), std::ios::binary);
    if (!input) throw config_error("cannot open configuration file: " + path);
    std::ostringstream buffer;
    char chunk[4096]; std::size_t total = 0;
    while (input.read(chunk, sizeof(chunk)) || input.gcount()) {
        total += static_cast<std::size_t>(input.gcount());
        if (total > 1024 * 1024) throw config_error("configuration exceeds 1 MiB");
        buffer.write(chunk, input.gcount());
    }
    if (input.bad()) throw config_error("cannot read configuration file: " + path);
    return parse_config(buffer.str());
}
std::string serialize_config(const Configure& config) {
    try {
        std::map<Network, Endpoint> owners;
        for (const auto& c : config.address_clients) for (const auto& n : c.networks)
            if (!owners.emplace(n, c.address).second) throw config_error("duplicate managed network");
        std::map<Network, IpAddress> local;
        for (const auto& n : config.networks) {
            if (local.count(n.tunnel)) throw config_error("cannot serialize duplicate local networks");
            if (n.allocation_server.port) {
                if (!owners.count(n.tunnel) || owners.at(n.tunnel) != n.allocation_server)
                    throw config_error("inconsistent address allocation authority");
                local[n.tunnel] = n.tunnel_ip;
            } else {
                if (owners.count(n.tunnel)) throw config_error("cannot serialize a static network with an allocation authority");
                add_local(n, "networks", local);
            }
        }
        for (const auto& owner : owners) if (!local.count(owner.first)) throw config_error("undeclared managed local network");
        json doc = json::object();
        const bool overlay = config.listen.address.port != 0;
        if (overlay) { doc["address"] = config.listen.address.str(); doc["networks"] = json::array(); }
        auto all_refs = json::array();
        for (const auto& item : local) {
            if (!owners.count(item.first)) doc["networks"].push_back(item.second.str() + "/" + std::to_string(item.first.prefix));
            all_refs.push_back(item.first.str());
        }
        if (doc.count("networks") && doc["networks"].empty()) doc.erase("networks");
        if (config.tun_mtu != 1280) doc["tun_mtu"] = config.tun_mtu;
        if (config.transport_mtu != 1500) doc["transport_mtu"] = config.transport_mtu;
        // Pin the resolved backend when saving: an explicit TUN selection must
        // survive normalization and moving a configuration to another platform.
        doc["device_backend"] = config.device_backend;
        auto listen = json::object();
        if (!config.listen.enabled) listen["enabled"] = false;
        auto default_bind = config.listen.address;
        default_bind.ip.bytes.fill(0);
        if (!(config.listen.bind_address == default_bind)) listen["bind_address"] = config.listen.bind_address.str();
        const auto listen_refs = serialized_refs(config.listen.networks, local);
        if (listen_refs != all_refs) listen["networks"] = listen_refs;
        if (overlay && !listen.empty()) doc["listen"] = listen;
        std::vector<const PeerConfig*> peers;
        for (const auto& peer : config.peers) peers.push_back(&peer);
        std::sort(peers.begin(), peers.end(), [](const PeerConfig* left, const PeerConfig* right) {
            return left->address < right->address;
        });
        for (const auto* peer : peers) {
            json value = {{"address", peer->address.str()}, {"shared_key", peer->shared_key}};
            if (peer->transport != "udp") value["transport"] = peer->transport;
            const auto refs = serialized_refs(peer->networks, local);
            if (refs.empty()) throw config_error("cannot serialize a peer without network authorization");
            // Never use an implicit all-networks permission for a multi-network
            // peer: adding a local address must not silently expand its access.
            if (local.size() != 1) value["networks"] = refs;
            doc["peers"].push_back(value);
        }
        for (const auto& c : config.address_clients) doc["address_clients"].push_back(service_client_json(c));
        for (const auto& r : config.advertise_routes) {
            json value = {{"tunnel", r.tunnel.str()}, {"prefix", r.prefix.str()}};
            if (r.snat) value["snat"] = true;
            doc["advertise_routes"].push_back(value);
        }
        const auto& remote = config.remote_desktop;
        if (remote.configured || remote.enabled || remote.unattended || !remote.networks.empty() ||
                remote.port != 47831 || !remote.device_name.empty() || remote.access != "authorized_devices") {
            json value = {{"enabled", remote.enabled}, {"networks", json::array()}};
            for (const auto& n : remote.networks) value["networks"].push_back(n.str());
            if (remote.access != "authorized_devices") value["access"] = remote.access;
            if (remote.unattended) value["unattended"] = true;
            if (remote.port != 47831) value["port"] = remote.port;
            if (!remote.device_name.empty()) value["device_name"] = remote.device_name;
            doc["remote_desktop"] = value;
        }
        if (config.address_server.enabled) {
            const auto& s = config.address_server;
            json value = {{"address", s.address.str()}, {"networks", json::array()}};
            if (!s.shared_key.empty()) {
                if (!s.clients.empty()) throw config_error("address_server: shared_key and clients are mutually exclusive");
                value["shared_key"] = s.shared_key;
            } else value["clients"] = json::array();
            auto bind = s.address; bind.ip.bytes.fill(0);
            if (s.bind_address != bind) value["bind_address"] = s.bind_address.str();
            if (s.state_file != "address-leases.json") value["state_file"] = s.state_file;
            if (s.reclaim_after != 86400) value["reclaim_after"] = s.reclaim_after;
            for (const auto& n : s.networks) value["networks"].push_back(n.str());
            for (const auto& c : s.clients) value["clients"].push_back(service_client_json(c));
            doc["address_server"] = value;
        }
        const auto text = doc.dump(2) + '\n';
        // Also validate caller-built Configure objects and the serialized size.
        // Parsed configurations can therefore be saved and loaded without a
        // hidden change of authorization or a non-loadable output document.
        parse_config(text);
        return text;
    } catch (const json::exception&) { throw config_error("cannot serialize configuration JSON"); }
}
Configure load_config(const std::string& path) { return parse_config_file(path); }
bool try_parse_config(const std::string& text, Configure* result, std::string* error) {
    if (!result) { if (error) *error = "result must not be null"; return false; }
    try { auto parsed = parse_config(text); *result = std::move(parsed); if (error) error->clear(); return true; }
    catch (const config_error& e) { if (error) *error = e.what(); return false; }
}
