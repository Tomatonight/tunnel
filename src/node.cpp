#include "node.h"
#include "kernel_device.h"
#include "tcp_transport.h"
#include "tls.h"
#include "peer.h"
#include "tunnel.h"
#include "address_service.h"
#include "return_flows.h"
#include <openssl/rand.h>
#include <algorithm>
#include <atomic>
#include <deque>
#include <list>
#include <set>

namespace {
using Clock = std::chrono::steady_clock;
using Time = Clock::time_point;
using Json = wire::Json;
using RouteKey = std::pair<Network, NodeId>;
long long elapsed(Time now, Time then) { return std::chrono::duration_cast<std::chrono::milliseconds>(now - then).count(); }
std::uint64_t random_token() {
    std::uint64_t value = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) throw std::runtime_error("probe randomness failed");
    return value ? value : 1;
}
std::uint64_t next_end_attempt() {
    // Survives host-owned Node recreation within one process identity lifetime.
    static std::atomic<std::uint64_t> counter{0};
    return ++counter;
}
Bytes probe_packet(unsigned char kind, std::uint64_t token) {
    Bytes b{kind}; for (int i = 56; i >= 0; i -= 8) b.push_back(static_cast<unsigned char>(token >> i)); return b;
}
std::string endpoints(const Endpoint& a, const Endpoint& b) { return a < b ? a.str() + "|" + b.str() : b.str() + "|" + a.str(); }
Bytes remote_payload(const Network& network, const NodeId& node, const IpAddress& ip, const Bytes& payload) {
    const auto prefix = "Tunnel remote desktop membership v1\n" + network.str() + "\n" + node.str() + "\n" + ip.str() + "\n";
    Bytes result(prefix.begin(), prefix.end()); result.insert(result.end(), payload.begin(), payload.end()); return result;
}
std::string remote_string(const Json& value, const char* name, std::size_t maximum) {
    const auto& entry = value.at(name);
    if (!entry.is_string()) throw std::invalid_argument("invalid_request");
    auto text = entry.get<std::string>();
    if (text.empty() || text.size() > maximum || text.find('\0') != std::string::npos)
        throw std::invalid_argument("invalid_request");
    return text;
}
}
struct Node::Impl {
    struct Link {
        Endpoint remote;
        bool client = false, dead = false, hello_sent = false, hello_received = false;
        std::unique_ptr<TlsChannel> tls;
        std::unique_ptr<TcpStream> tcp;
        std::unique_ptr<Peer> peer;
        std::unique_ptr<CryptoSession> crypto;
        wire::Decoder decoder;
        PublicKey key{};
        bool network_updates = false, data_tcp = false;
        std::map<Network, Endpoint> permitted;
        std::map<Network, IpAddress> remote_networks;
        std::map<Network, Json> remote_grants;
        std::map<Network, IpAddress> networks;
        std::map<RouteKey, std::string> advertised;
        std::uint64_t generation = 0, probe = 0;
        Time created = Clock::now(), heartbeat{}, proof_checked{};
    };
    struct EndSession {
        PublicKey key{};
        std::string id;
        std::uint64_t attempt = 0;
        bool client = false, announced = false, confirmed = false, sent_ready = false;
        std::unique_ptr<TlsChannel> tls;
        std::unique_ptr<CryptoSession> crypto;
        std::deque<Bytes> pending;
        Time created = Clock::now(), requested{}, progress = created;
    };
    EventLoop& loop;
    Configure config;
    NodeOptions options;
    std::shared_ptr<IdentityKey> identity;
    PublicKey key;
    Gossip routes;
    std::unique_ptr<PacketDevice> device;
    std::unique_ptr<UdpTransport> udp;
    std::unique_ptr<TcpListener> listener;
    std::unique_ptr<AddressService> address_service;
    std::map<Network, AddressService::Grant> grants;
    std::map<Network, std::string> address_errors;
    EventLoop::Handle timer;
    std::map<Network, Tunnel> tunnels;
    std::list<std::unique_ptr<Link>> links;
    std::map<Endpoint, Link*> active;
    std::map<SessionId, Link*> sessions;
    std::map<Endpoint, Time> retry;
    std::map<Endpoint, unsigned> attempts;
    std::map<RouteKey, EndSession> end_sessions;
    using SubnetKey = std::pair<Network, Network>;
    std::map<SubnetKey, NodeId> subnet_gateways;
    std::map<SubnetKey, std::string> subnet_errors;
    std::map<Network, ReturnFlows> return_flows;
    std::vector<AdvertisedRoute> active_exports;
    std::string exports_signature, imports_signature, export_error;
    Time subnet_retry{};
    std::map<std::string, std::uint64_t> counters;
    bool started = false, dirty = true, device_failed = false;
    std::string kernel_error;
    unsigned dispatch_depth = 0;
    bool invalidate_pending = false;
    struct Dispatch {
        Impl& node;
        explicit Dispatch(Impl& n) : node(n) { ++node.dispatch_depth; }
        ~Dispatch() {
            if (--node.dispatch_depth == 0) {
                if (node.invalidate_pending) node.invalidate_end();
                node.sync_kernel();
            }
        }
    };
    Impl(EventLoop& l, Configure c, std::unique_ptr<PacketDevice> d, NodeOptions o, Endpoint previous_server = {})
        : loop(l), config(std::move(c)), options(std::move(o)),
          identity(options.identity ? options.identity : std::make_shared<IdentityKey>()), key(identity->public_key()),
          routes(config.networks, config.advertise_routes), device(std::move(d)) {
        if ((!device && !config.networks.empty()) || !options.tick_ms || !options.heartbeat_ms || options.failure_timeout_ms <= options.heartbeat_ms ||
            !options.reconnect_ms || !options.handshake_timeout_ms || !options.session_lifetime_ms)
            throw std::invalid_argument("invalid node/device timing configuration");
        for (const auto& n : config.networks) if (!n.allocation_server.port) tunnels.emplace(n.tunnel, Tunnel(n, config.tun_mtu));
        if (config.address_server.enabled || !config.address_clients.empty()) {
            AddressService::Options service_options;
            service_options.tick_ms = options.tick_ms;
            service_options.heartbeat_ms = options.heartbeat_ms;
            service_options.failure_timeout_ms = options.failure_timeout_ms;
            service_options.handshake_timeout_ms = options.handshake_timeout_ms;
            service_options.reconnect_ms = options.reconnect_ms;
            service_options.proof_lifetime_ms = options.address_proof_lifetime_ms;
            service_options.previous_server = previous_server;
            service_options.protect = options.protect; service_options.log = options.log;
            address_service.reset(new AddressService(loop, config,
                [this](const Network& network, const AddressService::Grant* grant) { address_changed(network, grant); }, service_options));
        }
    }
    const PeerConfig* peer_config(const Endpoint& e) const {
        for (const auto& p : config.peers) if (p.address == e) return &p;
        return nullptr;
    }
    NodeId local_node(const Network& network) const {
        const auto active = tunnels.find(network);
        if (active != tunnels.end()) return active->second.config().tunnel_ip;
        for (const auto& n : config.networks) if (n.tunnel == network) return n.tunnel_ip;
        return NodeId{};
    }
    KernelDataPlane* kernel() const { return dynamic_cast<KernelDataPlane*>(device.get()); }
    void sync_kernel() noexcept {
        auto* k = kernel();
        if (!k || !started || device_failed) return;
        try {
            KernelState state;
            for (const auto& n : tunnels) state.networks.push_back(n.second.config());
            for (const auto& item : active) {
                const auto& l = *item.second;
                if (l.dead || !l.crypto || !l.peer) continue;
                KernelPeer p; p.endpoint = l.remote; p.crypto = l.crypto.get(); p.tcp = l.data_tcp;
                p.ready = l.peer->state() == PEER_STATE_ESTABLISHED;
                for (const auto& n : l.networks) if (tunnels.count(n.first)) p.networks.push_back(n.first);
                state.peers.push_back(std::move(p));
            }
            std::set<RouteKey> targets;
            for (const auto& p : routes.snapshot()) if (tunnels.count(p.network)) targets.insert({p.network, p.destination});
            for (const auto& p : active) for (const auto& n : p.second->networks)
                if (tunnels.count(n.first)) targets.insert({n.first, n.second});
            for (const auto& target : targets) {
                KernelRoute r; r.network = target.first; r.destination = target.second;
                if (!routes.ip_for_node(target.first, target.second, &r.ip)) continue;
                for (const auto& hop : routes.next_hops(target.first, target.second)) {
                    const auto it = active.find(hop);
                    if (it != active.end() && !it->second->dead && it->second->crypto && it->second->peer &&
                        it->second->peer->state() == PEER_STATE_ESTABLISHED && it->second->networks.count(target.first)) r.hops.push_back(hop);
                }
                if (r.hops.empty()) continue;
                state.routes.push_back(std::move(r));
                for (const auto& prefix : routes.prefixes_for_node(target.first, target.second)) {
                    KernelPrefix p; p.network = target.first; p.prefix = prefix; p.publisher = target.second;
                    const auto selected = subnet_gateways.find({target.first, prefix});
                    p.selected = selected != subnet_gateways.end() && selected->second == target.second;
                    state.prefixes.push_back(std::move(p));
                }
            }
            for (const auto& n : tunnels) for (const auto& prefix : routes.prefixes_for_node(n.first, local_node(n.first))) {
                KernelPrefix p; p.network = n.first; p.prefix = prefix; p.publisher = local_node(n.first); p.selected = true;
                state.prefixes.push_back(std::move(p));
            }
            for (const auto& entry : end_sessions) if (entry.second.crypto && tunnels.count(entry.first.first)) {
                KernelEnd e; e.network = entry.first.first; e.destination = entry.first.second;
                e.crypto = entry.second.crypto.get(); e.ready = entry.second.confirmed; state.ends.push_back(std::move(e));
            }
            k->update(state);
        } catch (const std::exception& error) {
            kernel_error = error.what(); ++counters["kernel_control_error"];
            log("kernel data plane stopped: " + kernel_error);
            // Fail closed on partial publication, never continue with stale keys
            // or an authorization set which the control plane has withdrawn.
            try { k->shutdown(); } catch (...) {}
            device_failed = true;
            for (auto& l : links) fail(*l);
            try { device->start({}); } catch (...) {}
        }
    }
    void kernel_event(KernelEvent event) {
        Dispatch dispatch(*this);
        if (!started || device_failed) return;
        auto* k = kernel(); if (!k) return;
        const auto found = active.find(event.peer);
        if (event.kind == KernelEvent::Tcp) {
            if (found == active.end()) return;
            auto& l = *found->second;
            if (l.dead || !l.crypto || !l.data_tcp || !l.hello_received) return;
            SessionId record_id;
            if (!CryptoSession::peek_session_id(event.packet, &record_id) || record_id != l.crypto->id()) return;
            // Ciphertext is already sequenced by the kernel. Whole-record loss
            // is legal; never remove bytes from an accepted TLS stream frame.
            if (l.tcp->pending_bytes() + event.packet.size() + 64 > 512 * 1024) { ++counters["tcp_data_send_drop"]; return; }
            try { l.tls->write(wire::data_frame(event.packet)); flush(l); }
            catch (...) { fail(l); }
        } else if (event.kind == KernelEvent::ProbeAck) {
            if (found == active.end()) return;
            auto& l = *found->second;
            if (l.dead || !l.peer) return;
            const auto before = l.peer->state();
            if (l.peer->authenticated_data_ack(l.generation, event.token, Clock::now())) {
                l.probe = 0; if (before != PEER_STATE_ESTABLISHED) established(l);
            }
        } else if (event.kind == KernelEvent::NeedSession) {
            const NodeId node = event.peer.ip;
            if (!tunnels.count(event.network) || routes.next_hops(event.network, node).empty()) return;
            ensure_end({event.network, node});
        } else if (event.kind == KernelEvent::Rekey) {
            if (event.network.address.family == 4 || event.network.address.family == 6) {
                const NodeId node = event.peer.ip;
                end_sessions.erase({event.network, node});
                if (tunnels.count(event.network)) ensure_end({event.network, node});
            } else if (found != active.end()) fail(*found->second);
        }
    }
    void log(const std::string& text) {
        // Host logging must not interrupt transport cleanup or rollback.
        if (options.log) try { options.log(text); } catch (...) {}
    }
    bool local_export(const Network& network, const IpAddress& ip) const {
        for (const auto& prefix : routes.prefixes_for_node(network, local_node(network)))
            if (prefix.usable_host(ip)) return true;
        return false;
    }
    bool published_by(const Network& network, const NodeId& node, const IpAddress& ip) const {
        for (const auto& prefix : routes.prefixes_for_node(network, node)) if (prefix.usable_host(ip)) return true;
        return false;
    }
    bool protects_transport(const Network& prefix) const {
        if (prefix.contains(config.listen.address.ip)) return true;
        for (const auto& peer : config.peers) if (prefix.contains(peer.address.ip)) return true;
        for (const auto& client : config.address_clients) if (prefix.contains(client.address.ip)) return true;
        if (config.address_server.enabled && prefix.contains(config.address_server.address.ip)) return true;
        for (const auto& path : routes.snapshot()) if (prefix.contains(path.destination)) return true;
        return false;
    }
    void sync_subnets(bool force = false) {
        if (!device || device_failed) return;
        const auto now = Clock::now();
        bool backend_attempt = false;
        std::vector<AdvertisedRoute> desired_exports; std::string export_signature;
        for (const auto& route : config.advertise_routes) if (tunnels.count(route.tunnel)) {
            desired_exports.push_back(route);
            export_signature += route.tunnel.str() + "/" + route.prefix.str() + (route.snat ? "/1;" : "/0;");
        }
        if (force || export_signature != exports_signature || (!export_error.empty() && now >= subnet_retry)) {
            backend_attempt = true;
            const auto previous = active_exports;
            try {
                device->set_exports(desired_exports); active_exports = desired_exports;
                exports_signature = export_signature; export_error.clear();
            } catch (const std::exception& error) {
                active_exports.clear(); exports_signature = export_signature; export_error = error.what();
                try { device->set_exports({}); } catch (...) {}
                ++counters["subnet_export_error"]; log("subnet export unavailable: " + export_error);
            }
            for (const auto& network : config.networks) {
                std::vector<Network> prefixes;
                for (const auto& route : active_exports) if (route.tunnel == network.tunnel) prefixes.push_back(route.prefix);
                routes.set_local_prefixes(network.tunnel, prefixes);
            }
            if (!previous.empty() || !active_exports.empty()) dirty = true;
        }
        std::vector<ImportedRoute> desired; std::map<SubnetKey, NodeId> gateways;
        std::map<SubnetKey, std::string> errors;
        for (const auto& network : tunnels) {
            std::set<Network> candidates;
            for (const auto& path : routes.snapshot()) if (path.network == network.first)
                for (const auto& prefix : path.prefixes) candidates.insert(prefix);
            for (const auto& prefix : candidates) {
                bool local = false;
                for (const auto& setting : config.advertise_routes) if (setting.prefix == prefix) local = true;
                if (local) continue; // Never redirect our own LAN back into TUN.
                const SubnetKey id{network.first, prefix}; NodeId gateway;
                if (!routes.select_gateway(network.first, prefix, &gateway)) { errors[id] = "conflicting or unreachable subnet announcement"; continue; }
                if (gateway == local_node(network.first)) continue;
                if (protects_transport(prefix)) { errors[id] = "subnet overlaps an overlay or allocation transport address"; continue; }
                ImportedRoute route; route.tunnel = network.first; route.prefix = prefix; route.source = network.second.config().tunnel_ip;
                desired.push_back(route); gateways[id] = gateway;
            }
        }
        std::string import_signature;
        for (const auto& route : desired) import_signature += route.tunnel.str() + "/" + route.prefix.str() + "/" + route.source.str() + ";";
        if (force || import_signature != imports_signature || (!subnet_errors.empty() && now >= subnet_retry)) {
            backend_attempt = true;
            try { device->set_routes(desired); imports_signature = import_signature; }
            catch (const std::exception& error) {
                // A local route conflict must not redirect an existing physical
                // network. Try the remaining prefixes independently.
                std::vector<ImportedRoute> accepted;
                try { device->set_routes({}); } catch (...) {}
                for (const auto& route : desired) {
                    const SubnetKey id{route.tunnel, route.prefix}; auto attempt = accepted; attempt.push_back(route);
                    try { device->set_routes(attempt); accepted = std::move(attempt); }
                    catch (const std::exception& detail) {
                        errors[id] = detail.what(); gateways.erase(id);
                        try { device->set_routes(accepted); } catch (...) { accepted.clear(); gateways.clear(); break; }
                    }
                }
                imports_signature = import_signature; ++counters["subnet_import_error"];
                log(std::string("subnet route installation: ") + error.what());
            }
        } else {
            // Keep platform failures fenced until the bounded retry.
            for (const auto& error : subnet_errors) if (gateways.count(error.first)) {
                errors[error.first] = error.second; gateways.erase(error.first);
            }
        }
        subnet_gateways = std::move(gateways); subnet_errors = std::move(errors);
        if (backend_attempt || now >= subnet_retry) subnet_retry = now + std::chrono::seconds(5);
        if (!device->healthy()) {
            device_failed = true; active_exports.clear(); subnet_gateways.clear(); return_flows.clear();
            for (const auto& n : config.networks) { routes.set_local_prefixes(n.tunnel, {}); routes.set_local_address(n.tunnel, nullptr); }
            tunnels.clear(); grants.clear();
            for (auto& link : links) fail(*link);
            device->start({}); invalidate_end(); dirty = true;
        }
    }
    std::string lookup_psk(const std::string& id) const {
        const auto bar = id.find('|'); if (bar == std::string::npos) return {};
        const auto initiator = Endpoint::parse(id.substr(0, bar));
        const auto responder = Endpoint::parse(id.substr(bar + 1));
        Endpoint remote;
        if (initiator == config.listen.address) remote = responder;
        else if (responder == config.listen.address) remote = initiator;
        else return {};
        const auto* p = peer_config(remote); return p ? p->shared_key : std::string();
    }
    void start() {
        if (started) return;
        Dispatch dispatch(*this);
        if (!device && !config.networks.empty()) throw std::runtime_error("virtual interface unavailable; reload required");
        if (device) {
        sync_subnets(true);
        if (device_failed) throw std::runtime_error("virtual interface unavailable during subnet configuration");
        if (auto* k = kernel()) k->on_event([this](KernelEvent event) { kernel_event(std::move(event)); });
        else udp.reset(new UdpTransport(loop, config.listen.bind_address,
            config.transport_mtu - protocol::outer_overhead(config.listen.address.ip.family),
            [this](const Endpoint& from, Bytes packet) { receive_udp(from, packet); }, options.protect));
        if (config.listen.enabled) listener.reset(new TcpListener(loop, config.listen.bind_address, [this](evutil_socket_t fd) {
            if (links.size() >= config.peers.size() * 2 + 16) { evutil_closesocket(fd); return; }
            make_link(false, Endpoint(), fd);
        }, options.protect));
        device->start([this](Bytes packet) { if (started) from_device(packet); });
        }
        started = true;
        if (address_service) address_service->start();
        timer = loop.addTimer(std::chrono::milliseconds(options.tick_ms), [this](evutil_socket_t, short) { tick(); }, true);
        if (!timer) throw std::runtime_error("node timer allocation failed");
        tick(); log("started " + (device ? config.listen.address.str() + " device=" + device->name() : std::string("address server")));
    }
    void stop() {
        // Also release partially started resources after a failed reload/start.
        Dispatch dispatch(*this);
        started = false; timer.reset(); listener.reset();
        if (address_service) address_service->stop();
        for (auto& l : links) fail(*l);
        links.clear(); end_sessions.clear(); udp.reset();
        return_flows.clear(); subnet_gateways.clear(); active_exports.clear();
        exports_signature.clear(); imports_signature.clear();
        for (const auto& n : config.networks) routes.set_local_prefixes(n.tunnel, {});
        if (device) {
            try { device->start({}); } catch (const std::exception& e) { log(std::string("device stop: ") + e.what()); }
            try { device->set_exports({}); } catch (const std::exception& e) { log(std::string("subnet export cleanup: ") + e.what()); }
            try { device->set_routes({}); } catch (const std::exception& e) { log(std::string("subnet route cleanup: ") + e.what()); }
        }
    }
    void replace_peers(Configure replacement, const std::set<Endpoint>& changed) {
        // Cancel unidentified inbound handshakes too: they may already have
        // consumed a PSK that has just been revoked by this configuration.
        for (auto& link : links) if (!link->remote.port || changed.count(link->remote)) fail(*link);
        for (const auto& remote : changed) {
            routes.forget_peer(remote); retry.erase(remote); attempts.erase(remote);
        }
        config = std::move(replacement);
        links.remove_if([](const std::unique_ptr<Link>& link) { return link->dead; });
        invalidate_end(); dirty = true;
        if (started) tick();
    }
    void fail(Link& l) {
        if (l.dead) return;
        l.dead = true;
        if (l.crypto) sessions.erase(l.crypto->id());
        auto it = active.find(l.remote);
        if (it != active.end() && it->second == &l) {
            active.erase(it); routes.set_available(l.remote, false); invalidate_end(); dirty = true;
            ++counters["peer_down"]; log("peer down " + l.remote.str());
        }
        if (l.peer) l.peer->disconnect();
        if (l.tcp) l.tcp->close();
        if (l.remote.port) {
            const auto backoff = std::min(8u, 1u << std::min(3u, attempts[l.remote]++));
            retry[l.remote] = Clock::now() + std::chrono::milliseconds(options.reconnect_ms * backoff);
        }
    }
    void make_link(bool client, Endpoint remote, evutil_socket_t fd = EVUTIL_INVALID_SOCKET) {
        std::unique_ptr<Link> link(new Link); auto* l = link.get();
        l->client = client; l->remote = remote;
        try {
            const auto id = client ? config.listen.address.str() + "|" + remote.str() : std::string();
            l->tls.reset(new TlsChannel(client, id, [this, client](const std::string& value) {
                if (!client) {
                    const auto bar = value.find('|');
                    if (bar == std::string::npos || value.substr(bar + 1) != config.listen.address.str()) return std::string();
                }
                return lookup_psk(value);
            }));
        } catch (...) { if (fd != static_cast<evutil_socket_t>(EVUTIL_INVALID_SOCKET)) evutil_closesocket(fd); throw; }
        links.push_back(std::move(link));
        try {
            l->tcp.reset(new TcpStream(loop, fd, options.protect,
                [this, l](const Bytes& b) { process_tcp(*l, b); },
                [this, l] { Dispatch dispatch(*this); try { l->tls->advance(); flush(*l); } catch (...) { fail(*l); } },
                [this, l] { Dispatch dispatch(*this); fail(*l); }));
            if (client) l->tcp->connect(remote);
        } catch (...) { fail(*l); }
    }
    void flush(Link& l) { if (!l.dead && !l.tcp->send(l.tls->drain())) fail(l); }
    void send(Link& l, const Json& message) {
        if (l.dead || !l.tls->ready()) return;
        try { l.tls->write(wire::frame(message)); flush(l); } catch (...) { fail(l); }
    }
    bool locally_allowed(const Link& l, const NetworkConfig& n) const {
        if (l.client) return true;
        for (const auto& listen : config.listen.networks) if (listen.tunnel == n.tunnel) return true;
        return false;
    }
    Json network_offers(const Link& l) const {
        Json result = Json::array();
        const auto* p = peer_config(l.remote);
        if (p) for (const auto& n : p->networks) if (locally_allowed(l, n)) {
            Json value{{"network", n.tunnel.str()}};
            if (n.allocation_server.port) value["server"] = n.allocation_server.str();
            result.push_back(value);
        }
        return result;
    }
    Json local_membership(const Link& l) const {
        Json result = Json::array();
        const auto* p = peer_config(l.remote);
        if (p) for (const auto& n : p->networks) {
            const auto local = tunnels.find(n.tunnel);
            if (!locally_allowed(l, n) || local == tunnels.end()) continue;
            if (l.hello_received && !l.permitted.count(n.tunnel)) continue;
            Json value{{"network", n.tunnel.str()}, {"ip", local->second.config().tunnel_ip.str()}};
            if (n.allocation_server.port) {
                const auto grant = grants.find(n.tunnel);
                if (grant == grants.end()) continue;
                value["server"] = n.allocation_server.str(); value["lease"] = grant->second.proof;
            }
            result.push_back(value);
        }
        return result;
    }
    void remote_membership(Link& l, const Json& list) {
        if (!list.is_array() || list.size() > 64) throw std::invalid_argument("membership networks");
        std::set<Network> seen;
        std::map<Network, IpAddress> remote;
        std::map<Network, Json> proofs;
        for (const auto& value : list) {
            const auto network = Network::parse(value.at("network").get<std::string>());
            if (!seen.insert(network).second) throw std::invalid_argument("duplicate membership network");
            const auto permitted = l.permitted.find(network);
            if (permitted == l.permitted.end()) continue;
            const auto ip = IpAddress::parse(value.at("ip").get<std::string>());
            if (!network.usable_host(ip)) throw std::invalid_argument("membership address");
            if (permitted->second.port) {
                if (!value.count("server") || !value.count("lease") ||
                    Endpoint::parse(value.at("server").get<std::string>()) != permitted->second) continue;
                proofs[network] = value.at("lease");
            } else if (value.count("server") || value.count("lease")) continue;
            remote[network] = ip;
        }
        l.remote_networks = std::move(remote); l.remote_grants = std::move(proofs);
    }
    void refresh_membership(Link& l) {
        if (l.dead || !l.hello_received) return;
        std::map<Network, IpAddress> selected;
        for (const auto& item : l.remote_networks) {
            const auto local = tunnels.find(item.first);
            if (local == tunnels.end() || local->second.config().tunnel_ip == item.second) continue;
            const auto permission = l.permitted.find(item.first);
            if (permission == l.permitted.end()) continue;
            if (permission->second.port) {
                IpAddress verified;
                const auto proof = l.remote_grants.find(item.first);
                if (!address_service || proof == l.remote_grants.end() ||
                    !address_service->verify_grant(l.remote, item.first, proof->second, &verified) || verified != item.second) continue;
            }
            selected.emplace(item.first, item.second);
        }
        l.proof_checked = Clock::now();
        if (selected == l.networks) return;
        const auto previous = l.networks;
        l.networks = std::move(selected);
        std::vector<Network> authorized;
        for (const auto& n : l.networks) authorized.push_back(n.first);
        routes.set_authorized_networks(l.remote, authorized);
        routes.set_peer_nodes(l.remote, l.networks);
        for (const auto& old : previous) {
            const auto current = l.networks.find(old.first);
            if (current == l.networks.end() || current->second != old.second)
                routes.withdraw(l.remote, old.first, old.second);
        }
        if (l.networks.empty()) { fail(l); return; }
        if (l.peer && l.peer->state() == PEER_STATE_ESTABLISHED) {
            for (const auto& n : l.networks) {
                const auto old = previous.find(n.first);
                if (old != previous.end() && old->second == n.second) continue;
                if (l.permitted.at(n.first).port) routes.confirm_allocated_address(n.first, n.second, n.second);
                PathAnnouncement a; a.network = n.first; a.destination = n.second; a.tunnel_ip = n.second;
                a.public_key = l.key; a.path.push_back(n.second);
                if (!routes.announce(l.remote, a)) ++counters["route_rejected"];
            }
        }
        invalidate_end(); dirty = true;
    }
    void address_changed(const Network& network, const AddressService::Grant* grant) {
        Dispatch dispatch(*this);
        if (device_failed) return;
        const NetworkConfig* configured = nullptr;
        for (const auto& n : config.networks) if (n.tunnel == network) configured = &n;
        if (!configured || !configured->allocation_server.port) return;
        if (grant && (grant->server != configured->allocation_server || !network.usable_host(grant->ip))) return;
        const auto current = tunnels.find(network);
        const bool changed = grant ? current == tunnels.end() || current->second.config().tunnel_ip != grant->ip : current != tunnels.end();
        if (changed) {
            // Fence traffic and remove every learned/local publication for this
            // network before touching the OS; unrelated networks stay usable.
            tunnels.erase(network); grants.erase(network);
            return_flows.erase(network);
            routes.set_local_address(network, nullptr); invalidate_end(); dirty = true;
            sync_kernel(); // Revoke the old permission before any blocking OS configuration.
            sync_subnets(true);
            if (device_failed) return;
            std::vector<NetworkConfig> desired;
            for (const auto& n : tunnels) desired.push_back(n.second.config());
            NetworkConfig effective = *configured;
            if (grant) { effective.tunnel_ip = grant->ip; desired.push_back(effective); }
            try {
                if (device) device->set_networks(desired);
                address_errors.erase(network);
                if (grant) {
                    tunnels.emplace(network, Tunnel(effective, config.tun_mtu));
                    routes.set_local_address(network, &effective.tunnel_ip);
                }
            } catch (const std::exception& e) {
                address_errors[network] = "cannot update virtual interface";
                ++counters["address_device_error"]; log("address configuration failed " + network.str() + ": " + e.what());
                if (device && !device->healthy()) {
                    device_failed = true; active_exports.clear(); subnet_gateways.clear(); return_flows.clear();
                    for (const auto& n : config.networks) { routes.set_local_prefixes(n.tunnel, {}); routes.set_local_address(n.tunnel, nullptr); }
                    tunnels.clear(); grants.clear();
                    for (auto& l : links) fail(*l);
                    device->start({}); invalidate_end();
                    log("virtual interface unavailable; all overlay networks stopped; reconnect required");
                }
            }
        }
        if (grant && tunnels.count(network)) grants[network] = *grant;
        else grants.erase(network);
        if (changed) sync_subnets(true);
        std::vector<Link*> targets;
        for (const auto& l : active) targets.push_back(l.second);
        for (auto* l : targets) if (!l->dead && l->hello_received) {
            if (l->network_updates) send(*l, {{"type", "membership"}, {"networks", local_membership(*l)}});
            refresh_membership(*l);
        }
        // A new local IP invalidated direct routes even if the remote address
        // remained unchanged. Rebuild only this network's direct records.
        if (grant && tunnels.count(network)) for (auto* l : targets) {
            if (l->dead || !l->peer || l->peer->state() != PEER_STATE_ESTABLISHED) continue;
            const auto remote = l->networks.find(network);
            if (remote == l->networks.end()) continue;
            PathAnnouncement a; a.network = network; a.destination = remote->second; a.tunnel_ip = remote->second;
            a.public_key = l->key; a.path.push_back(remote->second);
            if (changed) {
                if (routes.announce(l->remote, a)) dirty = true;
                // Local address replacement discarded indirect candidates too.
                // Ask for a fresh snapshot even when this peer's own IP stayed
                // unchanged and its export cache would otherwise suppress it.
                send(*l, {{"type", "sync"}, {"network", network.str()}});
            }
        }
        if (changed) {
            ++counters[grant && tunnels.count(network) ? "network_up" : "network_down"];
            log(std::string("network ") + (grant && tunnels.count(network) ? "active " : "inactive ") + network.str());
        }
    }
    void process_tcp(Link& l, const Bytes& bytes) {
        Dispatch dispatch(*this);
        if (l.dead) return;
        try {
            l.tls->feed(bytes);
            if (l.tls->ready() && !l.hello_sent) {
                if (!l.client) {
                    const auto id = l.tls->psk_identity(); l.remote = Endpoint::parse(id.substr(0, id.find('|')));
                }
                const auto* p = peer_config(l.remote); if (!p) throw std::runtime_error("unknown authenticated peer");
                l.hello_sent = true;
                send(l, {{"type", "hello"}, {"version", 1}, {"endpoint", config.listen.address.str()}, {"key", wire::hex(key)},
                    {"network_updates", true}, {"offers", network_offers(l)}, {"networks", local_membership(l)},
                    {"tcp_data", true}, {"transport", p->transport}});
            }
            l.decoder.append(l.tls->read());
            Json message; Bytes packet;
            while (!l.dead && l.decoder.next(message, packet)) {
                if (packet.empty()) message_received(l, message);
                else {
                    try {
                        if (!l.hello_received || !l.data_tcp || !l.crypto)
                            throw std::invalid_argument("TCP data was not negotiated");
                        if (packet.size() > config.transport_mtu - protocol::outer_overhead(config.listen.address.ip.family))
                            throw std::length_error("TCP data packet exceeds transport limit");
                        receive_record(l, packet);
                        l.peer->authenticated_tcp_activity(l.generation, Clock::now());
                        ++counters["tcp_data_received"];
                    } catch (...) { ++counters["tcp_data_rejected"]; throw; }
                }
            }
            flush(l);
        } catch (const std::exception& e) {
            ++counters["control_rejected"]; log("control rejected from " + l.remote.str() + ": " + e.what()); fail(l);
        }
    }
    void hello(Link& l, const Json& j) {
        if (l.hello_received || j.at("version") != 1 || !j.count("endpoint") ||
            Endpoint::parse(j.at("endpoint").get<std::string>()) != l.remote)
            throw std::invalid_argument("invalid peer hello");
        const auto* p = peer_config(l.remote); if (!p) throw std::invalid_argument("unknown peer");
        const auto requested_transport = j.value("transport", std::string("udp"));
        if (requested_transport != "udp" && requested_transport != "tcp")
            throw std::invalid_argument("invalid peer data transport");
        const bool tcp_supported = j.value("tcp_data", false);
        l.data_tcp = p->transport == "tcp" || requested_transport == "tcp";
        if (l.data_tcp && !tcp_supported)
            throw std::invalid_argument("peer does not support TCP data encapsulation; upgrade peer or select UDP");
        l.key = wire::key(j.at("key"));
        const auto& nets = j.at("networks");
        if (!nets.is_array() || nets.size() > 64) throw std::invalid_argument("hello networks");
        l.network_updates = j.value("network_updates", false);
        const auto& offers = l.network_updates ? j.at("offers") : nets;
        if (!offers.is_array() || offers.size() > 64) throw std::invalid_argument("hello offers");
        std::set<Network> seen;
        for (const auto& n : offers) {
            const auto network = Network::parse(n.at("network").get<std::string>());
            if (!seen.insert(network).second) throw std::invalid_argument("duplicate hello network");
            Endpoint server;
            if (n.count("server")) server = Endpoint::parse(n.at("server").get<std::string>());
            for (const auto& local : p->networks) if (network == local.tunnel) {
                if (!locally_allowed(l, local)) continue;
                if (local.allocation_server.port != 0 || server.port != 0) {
                    if (!l.network_updates || !local.allocation_server.port || server != local.allocation_server) continue;
                }
                l.permitted.emplace(network, server);
            }
        }
        if (l.permitted.empty()) throw std::invalid_argument("no authorized common network or allocator mismatch");
        remote_membership(l, nets);
        auto old = active.find(l.remote);
        if (old != active.end()) {
            const bool preferred = l.client == (config.listen.address < l.remote);
            const bool old_preferred = old->second->client == (config.listen.address < l.remote);
            if (!preferred || old_preferred) { fail(l); return; }
            fail(*old->second);
        }
        std::string context = endpoints(config.listen.address, l.remote);
        for (const auto& n : l.permitted) {
            context += "|" + n.first.str();
            if (n.second.port) context += "|allocator:" + n.second.str();
        }
        context += config.listen.address < l.remote ? "|" + wire::hex(key) + "|" + wire::hex(l.key) :
                                                     "|" + wire::hex(l.key) + "|" + wire::hex(key);
        // Keep the old UDP exporter context for compatibility. Bind TCP data
        // keys to the negotiated mode so records cannot cross transports.
        if (l.data_tcp) context += "|transport:tcp:v1";
        l.crypto = l.tls->session(CryptoScope::Link, context);
        l.peer.reset(new Peer(*p)); l.generation = l.peer->begin_connection();
        l.peer->tcp_authenticated(l.generation, Clock::now()); l.hello_received = true;
        active[l.remote] = &l; sessions[l.crypto->id()] = &l;
        refresh_membership(l);
        if (l.dead) return;
        if (l.networks.empty()) { fail(l); return; }
        dirty = true;
        heartbeat(l);
    }
    void established(Link& l) {
        routes.set_available(l.remote, true);
        for (const auto& n : l.networks) {
            if (l.permitted.at(n.first).port) routes.confirm_allocated_address(n.first, n.second, n.second);
            PathAnnouncement a; a.network = n.first; a.destination = n.second; a.tunnel_ip = n.second;
            a.public_key = l.key; a.path.push_back(n.second);
            if (!routes.announce(l.remote, a)) { fail(l); return; }
        }
        invalidate_end(); attempts[l.remote] = 0; dirty = true; ++counters["peer_up"];
        send(l, {{"type", "sync"}}); log("peer established " + l.remote.str() + " transport=" + (l.data_tcp ? "tcp" : "udp"));
    }
    void heartbeat(Link& l) {
        if (l.dead || !l.crypto) return;
        send(l, {{"type", "ping"}});
        if (!l.probe) l.probe = random_token();
        l.peer->sent_data_probe(l.probe);
        if (auto* k = kernel()) {
            sync_kernel();
            if (!device_failed && !k->probe(l.remote, l.probe)) ++counters["kernel_probe_drop"];
        } else send_data(l, probe_packet(4, l.probe));
        l.heartbeat = Clock::now();
    }
    void send_data(Link& l, const Bytes& plain) {
        if (l.dead || !l.crypto) return;
        if (kernel()) { ++counters["kernel_unexpected_userspace_data"]; return; }
        try {
            if (l.data_tcp) {
                // Bound bulk output and reserve space for control/keepalive.
                // Drop an entire new datagram before encrypting/framing, never
                // bytes of a frame already queued on the reliable stream.
                const bool probe = plain.size() == 9 && (plain[0] == 4 || plain[0] == 5);
                if (!probe && l.tcp->pending_bytes() + plain.size() + protocol::record_overhead + 64 > 512 * 1024) {
                    ++counters["tcp_data_send_drop"]; return;
                }
                l.tls->write(wire::data_frame(l.crypto->seal(plain))); flush(l);
                if (!l.dead) ++counters["tcp_data_sent"];
            } else if (udp) {
                if (!udp->send(l.remote, l.crypto->seal(plain))) ++counters["udp_send_drop"];
                else ++counters["udp_data_sent"];
            }
        }
        catch (...) { fail(l); }
    }
    void message_received(Link& l, const Json& j) {
        const auto type = j.at("type").get<std::string>();
        if (type == "hello") { hello(l, j); return; }
        if (!l.hello_received) throw std::invalid_argument("message before hello");
        l.peer->authenticated_tcp_activity(l.generation, Clock::now());
        if (type == "ping") { send(l, {{"type", "pong"}}); return; }
        if (type == "pong") return;
        if (type == "sync") {
            if (j.count("network")) {
                const auto network = Network::parse(j.at("network").get<std::string>());
                if (!l.permitted.count(network)) throw std::invalid_argument("unauthorized sync");
                for (auto it = l.advertised.begin(); it != l.advertised.end();) {
                    if (it->first.first == network) it = l.advertised.erase(it); else ++it;
                }
            } else l.advertised.clear();
            dirty = true; return;
        }
        if (type == "membership") {
            if (!l.network_updates) throw std::invalid_argument("membership update not negotiated");
            remote_membership(l, j.at("networks")); refresh_membership(l); return;
        }
        if (l.peer->state() != PEER_STATE_ESTABLISHED) return;
        if (type == "route") {
            const auto a = wire::route(j);
            if (routes.announce(l.remote, a)) { invalidate_end(); dirty = true; } else ++counters["route_rejected"];
        } else if (type == "withdraw") {
            const auto n = Network::parse(j.at("network").get<std::string>());
            const auto d = IpAddress::parse(j.at("node").get<std::string>());
            if (!l.permitted.count(n)) throw std::invalid_argument("unauthorized withdrawal");
            routes.withdraw(l.remote, n, d); invalidate_end(); dirty = true;
        } else if (type == "e2e") receive_end(l, j);
        else throw std::invalid_argument("unknown control message");
    }
    void publish() {
        dirty = false;
        std::vector<Link*> targets;
        for (const auto& item : active) targets.push_back(item.second);
        for (auto* target : targets) {
            auto& l = *target;
            if (l.dead || l.peer->state() != PEER_STATE_ESTABLISHED) continue;
            std::map<RouteKey, std::string> next;
            for (const auto& n : l.networks) {
                PathAnnouncement a; a.network = n.first; a.destination = local_node(n.first);
                a.tunnel_ip = local_node(n.first); a.public_key = key; a.path.push_back(local_node(n.first));
                a.prefixes = routes.active_local_prefixes(n.first);
                next[{a.network, a.destination}] = wire::route(a).dump();
            }
            for (const auto& a : routes.export_to(l.remote)) next[{a.network, a.destination}] = wire::route(a).dump();
            for (const auto& old : l.advertised) if (!next.count(old.first))
                send(l, {{"type", "withdraw"}, {"network", old.first.first.str()}, {"node", old.first.second.str()}});
            for (const auto& value : next) {
                auto old = l.advertised.find(value.first);
                if (old == l.advertised.end() || old->second != value.second) send(l, Json::parse(value.second));
            }
            l.advertised = std::move(next);
        }
        invalidate_end();
    }
    void invalidate_end() {
        if (dispatch_depth) { invalidate_pending = true; return; }
        invalidate_pending = false;
        for (auto it = end_sessions.begin(); it != end_sessions.end();) {
            PublicKey current; IpAddress address;
            if (!routes.ip_for_node(it->first.first, it->first.second, &address) ||
                !routes.public_key(it->first.first, it->first.second, &current) || current != it->second.key) {
                return_flows[it->first.first].erase_peer(it->first.second); it = end_sessions.erase(it);
            }
            else ++it;
        }
    }
    Link* next_link(const Network& network, const NodeId& node, std::uint64_t flow) {
        Endpoint next;
        if (!routes.select_unicast(network, node, flow, &next)) return nullptr;
        auto it = active.find(next);
        if (it == active.end() || it->second->dead || !it->second->networks.count(network) ||
            it->second->peer->state() != PEER_STATE_ESTABLISHED) return nullptr;
        return it->second;
    }
    void route_end(Json message) {
        const auto network = Network::parse(message.at("network").get<std::string>());
        const auto destination = IpAddress::parse(message.at("destination").get<std::string>());
        auto* next = next_link(network, destination, 0);
        if (next) send(*next, message); else ++counters["no_route"];
    }
    Json end_message(const RouteKey& target, const std::string& op) {
        return {{"type", "e2e"}, {"network", target.first.str()}, {"source", local_node(target.first).str()},
            {"destination", target.second.str()}, {"op", op}, {"hops", protocol::default_hop_limit}};
    }
    void flush_end(const RouteKey& target, EndSession& s) {
        auto bytes = s.tls->drain();
        for (std::size_t offset = 0; offset < bytes.size(); offset += 16384) {
            const auto count = std::min<std::size_t>(16384, bytes.size() - offset);
            auto message = end_message(target, s.client && !s.announced ? "start" : "tls");
            message["id"] = s.id; message["data"] = wire::hex(bytes.data() + offset, count);
            if (s.client && !s.announced) message["attempt"] = s.attempt;
            s.announced = true; route_end(std::move(message));
        }
    }
    void progress_end(const RouteKey& target, EndSession& s) {
        if (s.tls->ready() && !s.crypto) {
            const auto context = target.first.str() + "|" + local_node(target.first).str() + "|" + target.second.str() + "|" + s.id;
            s.crypto = s.tls->session(CryptoScope::EndToEnd, context);
        }
        if (s.crypto && !s.sent_ready) { s.tls->write(Bytes{1}); s.sent_ready = true; }
        auto application = s.tls->read();
        if (!application.empty()) {
            if (application != Bytes{1}) throw std::invalid_argument("invalid end-to-end confirmation");
            if (!s.confirmed) { ++counters["e2e_established"]; s.confirmed = true; }
        }
        flush_end(target, s);
        if (s.confirmed) while (!s.pending.empty()) {
            auto packet = std::move(s.pending.front()); s.pending.pop_front(); send_unicast(target, s, packet);
        }
    }
    void begin_end(const RouteKey& target, EndSession& s) {
        // Routed TLS records can be lost while an intermediate path changes.
        // Retry with a fresh TLS session/id, never replay bytes into an existing
        // TLS stream. Keep the original deadline and queued IP packets bounded.
        s.id = wire::hex(random_session_id()); s.attempt = next_end_attempt(); s.announced = false;
        s.confirmed = false; s.sent_ready = false; s.crypto.reset();
        s.tls.reset(new TlsChannel(true, *identity, s.key));
        s.progress = Clock::now(); s.tls->advance(); flush_end(target, s);
    }
    EndSession* ensure_end(const RouteKey& target) {
        auto it = end_sessions.find(target);
        if (it != end_sessions.end()) return &it->second;
        PublicKey remote;
        if (end_sessions.size() >= 256 || !routes.public_key(target.first, target.second, &remote) ||
            routes.next_hops(target.first, target.second).empty()) return nullptr;
        auto& s = end_sessions[target]; s.key = remote;
        s.client = local_node(target.first) < target.second;
        if (s.client) begin_end(target, s);
        else { route_end(end_message(target, "request")); s.requested = Clock::now(); }
        return &s;
    }
    void receive_end(Link& incoming, Json j) {
        const auto n = Network::parse(j.at("network").get<std::string>());
        const auto source = IpAddress::parse(j.at("source").get<std::string>());
        const auto destination = IpAddress::parse(j.at("destination").get<std::string>());
        const auto hops = j.at("hops").get<unsigned>();
        if (!hops || hops > protocol::default_hop_limit || !incoming.networks.count(n) || source == local_node(n) ||
            !source.unicast() || !destination.unicast()) { ++counters["control_rejected"]; return; }
        if (destination != local_node(n)) {
            if (hops == 1) { ++counters["hop_limit_drop"]; return; }
            auto* next = next_link(n, destination, 0);
            if (next && next != &incoming) { j["hops"] = hops - 1; send(*next, j); ++counters["control_forwarded"]; }
            return;
        }
        const RouteKey target{n, source}; PublicKey remote;
        if (!tunnels.count(n) || !routes.public_key(n, source, &remote) || routes.next_hops(n, source).empty()) return;
        const auto op = j.at("op").get<std::string>();
        if (op == "request") {
            if (!(local_node(n) < source)) return;
            auto it = end_sessions.find(target);
            if (it != end_sessions.end() && it->second.confirmed && elapsed(Clock::now(), it->second.created) >= options.heartbeat_ms)
                end_sessions.erase(it);
            ensure_end(target); return;
        }
        const auto id = j.at("id").get<std::string>();
        if (wire::unhex(id, 16).size() != 16) throw std::invalid_argument("end-to-end session id");
        auto bytes = wire::unhex(j.at("data").get<std::string>(), 16384);
        if (bytes.empty()) throw std::invalid_argument("empty handshake record");
        auto it = end_sessions.find(target);
        if (op == "start") {
            if (!(source < local_node(n))) return;
            std::uint64_t attempt = 0;
            if (j.count("attempt")) {
                if (!j.at("attempt").is_number_unsigned() || !(attempt = j.at("attempt").get<std::uint64_t>()))
                    throw std::invalid_argument("end-to-end attempt number");
            }
            // Ignore an older attempt arriving through a previously selected
            // path; it must never replace the newer (possibly ready) session.
            if (it != end_sessions.end() && it->second.key == remote &&
                (it->second.id == id || (it->second.attempt && attempt <= it->second.attempt))) return;
            if (it == end_sessions.end() || it->second.id != id) {
                if (it == end_sessions.end() && end_sessions.size() >= 256) return;
                std::deque<Bytes> pending;
                if (it != end_sessions.end()) { pending.swap(it->second.pending); end_sessions.erase(it); }
                auto& s = end_sessions[target]; s.key = remote; s.id = id; s.attempt = attempt; s.pending.swap(pending);
                s.tls.reset(new TlsChannel(false, *identity, remote));
                it = end_sessions.find(target);
            }
        } else if (op != "tls") throw std::invalid_argument("unknown end-to-end operation");
        if (it == end_sessions.end() || it->second.id != id || !it->second.tls) return;
        try {
            it->second.tls->feed(bytes); progress_end(target, it->second);
            it->second.progress = Clock::now();
        }
        catch (...) { ++counters["e2e_rejected"]; end_sessions.erase(target); }
    }
    bool imported_gateway(const Network& network, const IpAddress& ip, NodeId* peer) const {
        for (const auto& item : subnet_gateways) if (item.first.first == network && item.first.second.usable_host(ip)) {
            *peer = item.second; return true;
        }
        return false;
    }
    void queue_unicast(const RouteKey& target, const Bytes& packet) {
        auto* session = ensure_end(target);
        if (!session) { ++counters["session_limit_drop"]; return; }
        if (session->confirmed) send_unicast(target, *session, packet);
        else if (session->pending.size() < 64) session->pending.push_back(packet);
        else ++counters["pending_drop"];
    }
    void send_unicast(const RouteKey& target, EndSession& s, const Bytes& packet) {
        PacketInfo info;
        const auto tunnel = tunnels.find(target.first);
        if (tunnel == tunnels.end() || !tunnel->second.inspect(packet, &info, false, true) || info.kind != protocol::PacketKind::Unicast) return;
        if (info.source == tunnel->second.config().tunnel_ip) {
            if (target.first.usable_host(info.destination)) {
                NodeId destination;
                if (!routes.node_for_ip(target.first, info.destination, &destination) || destination != target.second) return;
            } else {
                NodeId current;
                if (!imported_gateway(target.first, info.destination, &current) || !published_by(target.first, target.second, info.destination) ||
                    !return_flows[target.first].remember(packet, target.second)) { ++counters["subnet_request_drop"]; return; }
            }
        } else {
            NodeId destination; IpAddress requested; bool related = false;
            if (!return_flows[target.first].reply(packet, &destination, &related, Clock::now(), &requested) || destination != target.second ||
                !local_export(target.first, requested) || (!related && !local_export(target.first, info.source))) {
                ++counters["subnet_unsolicited_drop"]; return;
            }
        }
        protocol::ForwardHeader header; header.network = target.first; header.source = local_node(target.first);
        header.destination = target.second; header.flow_id = info.flow_id;
        auto* next = next_link(target.first, target.second, info.flow_id);
        if (!next) { ++counters["no_route"]; return; }
        try {
            const auto encrypted = s.crypto->seal(packet, protocol::end_to_end_aad(header));
            send_data(*next, protocol::encode(header, encrypted)); ++counters["unicast_sent"];
        } catch (...) { ++counters["e2e_send_drop"]; s.created = Time{}; }
    }
    void flood(const protocol::ForwardHeader& header, const Bytes& packet, Link* excluded) {
        const auto encoded = protocol::encode(header, packet);
        std::vector<Link*> targets; for (const auto& p : active) targets.push_back(p.second);
        for (auto* l : targets) if (l != excluded && !l->dead && l->networks.count(header.network) &&
            l->peer->state() == PEER_STATE_ESTABLISHED) send_data(*l, encoded);
    }
    void from_device(const Bytes& packet) {
        if (device_failed) return;
        Dispatch dispatch(*this);
        try {
            for (const auto& item : tunnels) {
                PacketInfo info; if (!item.second.inspect(packet, &info, false, true)) continue;
                const auto local = item.second.config().tunnel_ip;
                if (info.source != local) {
                    // The LAN may only return packets for requests which this
                    // gateway previously delivered. No LAN-initiated sessions.
                    NodeId destination; IpAddress requested; bool related = false;
                    auto flows = return_flows.find(item.first);
                    if (info.kind != protocol::PacketKind::Unicast || flows == return_flows.end() ||
                        !flows->second.reply(packet, &destination, &related, Clock::now(), &requested) ||
                        !local_export(item.first, requested) || (!related && !local_export(item.first, info.source))) continue;
                    IpAddress original;
                    if (!routes.ip_for_node(item.first, destination, &original) || original != info.destination) continue;
                    ++counters["tun_read"]; ++counters["subnet_replies_sent"];
                    queue_unicast({item.first, destination}, packet); return;
                }
                ++counters["tun_read"];
                if (info.kind != protocol::PacketKind::Unicast) {
                    if (!item.second.inspect(packet, &info, true)) continue;
                    protocol::ForwardHeader h; h.kind = info.kind; h.network = item.first;
                    h.source = local_node(item.first); h.flow_id = info.flow_id;
                    flood(h, packet, nullptr); ++counters["flood_sent"]; return;
                }
                if (info.destination == item.second.config().tunnel_ip) { device->send(packet); return; }
                NodeId destination;
                if (item.first.usable_host(info.destination)) {
                    if (!routes.node_for_ip(item.first, info.destination, &destination)) { ++counters["no_route"]; return; }
                } else {
                    if (!imported_gateway(item.first, info.destination, &destination)) { ++counters["no_route"]; return; }
                    NodeId previous;
                    if (return_flows[item.first].request_peer(packet, &previous) && published_by(item.first, previous, info.destination) &&
                        !routes.next_hops(item.first, previous).empty()) destination = previous;
                    if (!return_flows[item.first].remember(packet, destination)) { ++counters["subnet_request_drop"]; return; }
                }
                queue_unicast({item.first, destination}, packet);
                return;
            }
            ++counters["subnet_unsolicited_drop"];
            ++counters["invalid_tun_packet"];
        } catch (...) { ++counters["tun_packet_error"]; }
    }
    void deliver(const Bytes& bytes) { if (device->send(bytes)) ++counters["tun_written"]; else ++counters["tun_write_drop"]; }
    void forward(Link& incoming, const Bytes& plain) {
        protocol::ForwardHeader h; Bytes payload;
        if (!protocol::decode(plain, &h, &payload) || !incoming.networks.count(h.network) || !tunnels.count(h.network) ||
            h.source == local_node(h.network)) { ++counters["invalid_forward"]; return; }
        if (h.kind == protocol::PacketKind::Unicast) {
            if (h.destination != local_node(h.network)) {
                if (h.hop_limit <= 1) { ++counters["hop_limit_drop"]; return; }
                auto* next = next_link(h.network, h.destination, h.flow_id);
                if (next && next != &incoming) { --h.hop_limit; send_data(*next, protocol::encode(h, payload)); ++counters["unicast_forwarded"]; }
                else ++counters["no_route"];
                return;
            }
            auto it = end_sessions.find({h.network, h.source}); Bytes packet;
            if (it == end_sessions.end() || !it->second.crypto ||
                !it->second.crypto->open(payload, packet, protocol::end_to_end_aad(h))) { ++counters["e2e_decrypt_drop"]; return; }
            PacketInfo info; IpAddress source;
            if (!tunnels.at(h.network).inspect(packet, &info, false, true) || info.kind != h.kind || info.flow_id != h.flow_id ||
                !routes.ip_for_node(h.network, h.source, &source)) { ++counters["invalid_inner"]; return; }
            if (info.source == source) {
                if (info.destination != tunnels.at(h.network).config().tunnel_ip) {
                    if (!local_export(h.network, info.destination) || !return_flows[h.network].remember(packet, h.source)) {
                        ++counters["invalid_inner"]; return;
                    }
                    ++counters["subnet_requests_delivered"];
                }
            } else {
                NodeId gateway; IpAddress requested; bool related = false;
                if (info.destination != tunnels.at(h.network).config().tunnel_ip ||
                    !return_flows[h.network].reply(packet, &gateway, &related, Clock::now(), &requested) || gateway != h.source ||
                    !published_by(h.network, h.source, requested) || (!related && !published_by(h.network, h.source, info.source))) {
                    ++counters["subnet_unsolicited_drop"]; return;
                }
                ++counters["subnet_replies_received"];
            }
            deliver(packet);
        } else {
            if (!routes.accept_rpf(h.network, h.source, incoming.remote)) { ++counters["rpf_drop"]; return; }
            PacketInfo info; IpAddress source;
            if (!tunnels.at(h.network).inspect(payload, &info, false) || info.kind != h.kind || info.flow_id != h.flow_id ||
                !routes.ip_for_node(h.network, h.source, &source) || info.source != source ||
                info.source == tunnels.at(h.network).config().tunnel_ip) { ++counters["invalid_inner"]; return; }
            deliver(payload);
            if (h.hop_limit > 1) { --h.hop_limit; flood(h, payload, &incoming); ++counters["flood_forwarded"]; }
        }
    }
    void receive_record(Link& l, const Bytes& packet) {
        if (auto* k = kernel()) {
            if (!l.data_tcp || !k->receive_tcp(l.remote, packet)) throw std::invalid_argument("kernel rejected TCP data record");
            return;
        }
        Bytes plain;
        if (!l.crypto->open(packet, plain)) throw std::invalid_argument("invalid encrypted data record");
        if (plain.size() == 9 && (plain[0] == 4 || plain[0] == 5)) {
            std::uint64_t token = 0; for (std::size_t i = 1; i < plain.size(); ++i) token = (token << 8) | plain[i];
            if (plain[0] == 4) send_data(l, probe_packet(5, token));
            else {
                const auto state = l.peer->state();
                if (l.peer->authenticated_data_ack(l.generation, token, Clock::now())) {
                    l.probe = 0; if (state != PEER_STATE_ESTABLISHED) established(l);
                }
            }
        } else if (l.peer->state() == PEER_STATE_ESTABLISHED) forward(l, plain);
    }
    void receive_udp(const Endpoint& from, const Bytes& packet) {
        Dispatch dispatch(*this);
        SessionId id;
        if (!CryptoSession::peek_session_id(packet, &id)) { ++counters["udp_rejected"]; return; }
        const auto it = sessions.find(id);
        if (it == sessions.end() || it->second->dead || it->second->remote != from || it->second->data_tcp) {
            ++counters["udp_rejected"]; return;
        }
        auto& l = *it->second;
        try {
            receive_record(l, packet); ++counters["udp_data_received"];
        } catch (...) { ++counters["udp_rejected"]; }
    }
    void tick() {
        Dispatch dispatch(*this);
        if (!started) return;
        if (auto* k = kernel()) {
            if (!device_failed) try { k->renew(); }
            catch (const std::exception& error) {
                kernel_error = error.what(); device_failed = true;
                try { k->shutdown(); } catch (...) {}
                for (auto& l : links) fail(*l);
            }
        }
        const auto now = Clock::now();
        for (auto& l : links) if (!l->dead) {
            if (!l->hello_received && elapsed(now, l->created) >= options.handshake_timeout_ms) {
                ++counters["handshake_timeout"]; fail(*l);
            } else if (l->peer && l->peer->expired(now, std::chrono::milliseconds(options.failure_timeout_ms))) {
                ++counters["peer_timeout"]; log("peer activity timeout " + l->remote.str()); fail(*l);
            } else if (elapsed(now, l->created) >= options.session_lifetime_ms) fail(*l);
            else if (l->hello_received && elapsed(now, l->heartbeat) >= options.heartbeat_ms) heartbeat(*l);
            if (!l->dead && l->hello_received && l->network_updates && elapsed(now, l->proof_checked) >= 1000)
                refresh_membership(*l);
        }
        links.remove_if([](const std::unique_ptr<Link>& l) { return l->dead; });
        for (const auto& p : config.peers) {
            if (device_failed) break;
            bool joined = false;
            for (const auto& n : p.networks) if (tunnels.count(n.tunnel)) joined = true;
            if (!joined) continue;
            if (active.count(p.address) || (retry.count(p.address) && now < retry[p.address])) continue;
            bool pending = false; for (const auto& l : links) if (!l->dead && l->client && l->remote == p.address) pending = true;
            if (!pending) make_link(true, p.address);
        }
        if (dirty || now >= subnet_retry) sync_subnets();
        if (dirty) publish();
        for (auto& flows : return_flows) flows.second.expire(now);
        for (auto it = end_sessions.begin(); it != end_sessions.end();) {
            auto& s = it->second;
            if (elapsed(now, s.created) >= options.session_lifetime_ms ||
                (!s.confirmed && elapsed(now, s.created) >= options.handshake_timeout_ms)) {
                counters["pending_drop"] += s.pending.size(); it = end_sessions.erase(it);
            } else {
                if (!s.tls && elapsed(now, s.requested) >= options.heartbeat_ms) {
                    route_end(end_message(it->first, "request")); s.requested = now;
                }
                if (s.client && !s.confirmed && elapsed(now, s.progress) >= std::max(500u, options.heartbeat_ms)) {
                    begin_end(it->first, s); ++counters["e2e_handshake_retried"];
                }
                ++it;
            }
        }
    }
    Json remote_control(const std::string& text) const {
        Json id = nullptr;
        try {
            if (text.size() > 16384) throw std::invalid_argument("request_too_large");
            std::vector<std::set<std::string>> object_keys;
            const auto request = Json::parse(text, [&](int depth, Json::parse_event_t event, Json& value) {
                if (depth > 4) throw std::invalid_argument("invalid_request");
                if (event == Json::parse_event_t::object_start) object_keys.emplace_back();
                else if (event == Json::parse_event_t::key && !object_keys.back().insert(value.get<std::string>()).second)
                    throw std::invalid_argument("invalid_request");
                else if (event == Json::parse_event_t::object_end) object_keys.pop_back();
                return true;
            });
            if (!request.is_object() || !request.count("id")) throw std::invalid_argument("invalid_request");
            const auto& requested_id = request.at("id");
            if (!((requested_id.is_number_integer() && requested_id >= 0 && requested_id <= 9007199254740991ULL) ||
                    (requested_id.is_string() && !requested_id.get<std::string>().empty() && requested_id.get<std::string>().size() <= 64)))
                throw std::invalid_argument("invalid_request");
            id = requested_id;
            const auto method = remote_string(request, "method", 32);
            std::set<std::string> allowed{"id", "method"};
            if (method == "remote_sign" || method == "remote_verify") {
                allowed.insert("network"); allowed.insert("payload");
                if (method == "remote_verify") { allowed.insert("node"); allowed.insert("source_ip"); allowed.insert("signature"); }
            } else if (method != "remote_info") throw std::invalid_argument("unknown_method");
            for (auto it = request.begin(); it != request.end(); ++it)
                if (!allowed.count(it.key())) throw std::invalid_argument("invalid_request");
            Json result;
            if (method == "remote_info") {
                const auto& remote = config.remote_desktop;
                Json selected = Json::array(); for (const auto& n : remote.networks) selected.push_back(n.str());
                result = {{"endpoint", config.listen.address.port ? config.listen.address.str() : std::string()},
                    {"public_key", wire::hex(key)}, {"networks", Json::array()},
                    {"remote_desktop", {{"enabled", remote.enabled}, {"networks", selected}, {"access", remote.access},
                        {"unattended", remote.unattended}, {"port", remote.port}, {"device_name", remote.device_name}}}};
                if (started && !device_failed) for (const auto& entry : tunnels)
                    result["networks"].push_back({{"network", entry.first.str()}, {"tunnel_ip", entry.second.config().tunnel_ip.str()}});
            } else {
                const auto network_text = remote_string(request, "network", 64);
                const auto network = Network::parse(network_text);
                if (network.str() != network_text) throw std::invalid_argument("invalid_request");
                const auto payload = wire::unhex(remote_string(request, "payload", 8192), 4096);
                const auto local = tunnels.find(network);
                if (method == "remote_sign") {
                    if (!started || device_failed || local == tunnels.end()) throw std::invalid_argument("inactive_network");
                    const auto& ip = local->second.config().tunnel_ip;
                    result = {{"node", ip.str()}, {"network", network.str()}, {"source_ip", ip.str()},
                        {"signature", wire::hex(identity->sign(remote_payload(network, ip, ip, payload)))}};
                } else {
                    const auto node_text = remote_string(request, "node", 80);
                    const auto source_text = remote_string(request, "source_ip", 64);
                    const auto node = IpAddress::parse(node_text);
                    const auto source = IpAddress::parse(source_text);
                    const auto signature = wire::unhex(remote_string(request, "signature", 128), 64);
                    if (node.str() != node_text || source.str() != source_text || signature.size() != 64)
                        throw std::invalid_argument("invalid_request");
                    bool reachable = false, valid = false;
                    PublicKey remote_key{}; IpAddress current_ip;
                    if (started && !device_failed && local != tunnels.end() && node != local_node(network)) {
                        for (const auto& next : routes.next_hops(network, node)) {
                            const auto link = active.find(next);
                            if (link != active.end() && !link->second->dead && link->second->networks.count(network) &&
                                    link->second->peer && link->second->peer->state() == PEER_STATE_ESTABLISHED &&
                                    !link->second->peer->expired(Clock::now(), std::chrono::milliseconds(options.failure_timeout_ms))) {
                                reachable = true; break;
                            }
                        }
                        valid = reachable && routes.ip_for_node(network, node, &current_ip) && current_ip == source &&
                            routes.public_key(network, node, &remote_key) && IdentityKey::verify(remote_key, remote_payload(network, node, source, payload), signature);
                    }
                    result = {{"valid", valid}, {"node", node.str()}, {"network", network.str()}, {"source_ip", source.str()}};
                }
            }
            return {{"id", id}, {"ok", true}, {"result", result}};
        } catch (const std::invalid_argument& error) {
            // Parsing helpers also throw; expose only our bounded vocabulary.
            const std::string reason(error.what());
            return {{"id", id}, {"ok", false}, {"error", reason == "inactive_network" || reason == "unknown_method" ||
                reason == "request_too_large" ? reason : "invalid_request"}};
        } catch (const Json::exception&) {
            return {{"id", id}, {"ok", false}, {"error", "invalid_request"}};
        } catch (const std::exception&) {
            return {{"id", id}, {"ok", false}, {"error", "request_failed"}};
        }
    }
    Json status() const {
        unsigned pending_connections = 0;
        for (const auto& l : links) if (!l->dead && !l->hello_received) ++pending_connections;
        Json result{{"endpoint", config.listen.address.port ? config.listen.address.str() : std::string()},
                    {"network_identities", Json::array()}, {"public_key", wire::hex(key)}, {"device", device ? device->name() : std::string()},
                    {"pending_connections", pending_connections},
                    {"running", started}, {"counters", counters}, {"peers", Json::array()}, {"routes", Json::array()},
                    {"end_sessions", Json::array()}, {"networks", Json::array()}, {"address_errors", Json::object()}};
        result["device_backend"] = config.device_backend;
        result["device_error"] = device_failed ? (kernel_error.empty() ? "virtual interface unavailable; reconnect required" : kernel_error) : "";
        if (auto* k = kernel()) for (const auto& counter : k->statistics()) result["counters"][counter.first] = counter.second;
        result["subnet_routes"] = Json::array(); result["local_exports"] = Json::array();
        for (const auto& route : subnet_gateways) result["subnet_routes"].push_back({
            {"network", route.first.first.str()}, {"prefix", route.first.second.str()}, {"gateway", route.second.str()}, {"state", "active"}, {"error", ""}});
        for (const auto& error : subnet_errors) result["subnet_routes"].push_back({
            {"network", error.first.first.str()}, {"prefix", error.first.second.str()}, {"gateway", ""}, {"state", "error"}, {"error", error.second}});
        for (const auto& route : config.advertise_routes) {
            bool available = false;
            for (const auto& active : active_exports) if (active.tunnel == route.tunnel && active.prefix == route.prefix) available = true;
            std::string error = export_error;
            const auto usable = routes.prefixes_for_node(route.tunnel, local_node(route.tunnel));
            if (available && std::find(usable.begin(), usable.end(), route.prefix) == usable.end()) {
                available = false; error = "conflicting subnet announcement";
            }
            result["local_exports"].push_back({{"network", route.tunnel.str()}, {"prefix", route.prefix.str()}, {"snat", route.snat},
                {"active", available}, {"error", available || !tunnels.count(route.tunnel) ? std::string() : error}});
        }
        if (address_service) result["address_service"] = address_service->status();
        for (const auto& n : config.networks) {
            const auto active_network = tunnels.find(n.tunnel);
            Json entry{{"network", n.tunnel.str()}, {"managed", n.allocation_server.port != 0},
                {"active", active_network != tunnels.end()}, {"ip", active_network == tunnels.end() ? std::string() : active_network->second.config().tunnel_ip.str()}};
            result["network_identities"].push_back({{"network", n.tunnel.str()}, {"ip", entry["ip"]}});
            if (n.allocation_server.port) entry["server"] = n.allocation_server.str();
            result["networks"].push_back(entry);
        }
        for (const auto& error : address_errors) result["address_errors"][error.first.str()] = error.second;
        for (const auto& p : config.peers) {
            auto it = active.find(p.address);
            Json networks = Json::array();
            Json identities = Json::object();
            if (it != active.end()) for (const auto& n : it->second->networks) {
                networks.push_back(n.first.str()); identities[n.first.str()] = n.second.str();
            }
            result["peers"].push_back({{"endpoint", p.address.str()}, {"state", it == active.end() ? 0 : int(it->second->peer->state())},
                {"networks", networks}, {"identities", identities}, {"configured_transport", p.transport},
                {"transport", it == active.end() ? p.transport : (it->second->data_tcp ? "tcp" : "udp")}});
        }
        std::set<RouteKey> seen;
        for (const auto& a : routes.snapshot()) seen.insert({a.network, a.destination});
        // Direct destinations may be excluded from every split-horizon export.
        for (const auto& p : active) for (const auto& n : p.second->networks)
            if (!routes.next_hops(n.first, n.second).empty()) seen.insert({n.first, n.second});
        for (const auto& target : seen) {
            Json hops = Json::array(); for (const auto& h : routes.next_hops(target.first, target.second)) hops.push_back(h.str());
            PublicKey pub{}; routes.public_key(target.first, target.second, &pub);
            IpAddress ip; const bool has_ip = routes.ip_for_node(target.first, target.second, &ip);
            result["routes"].push_back({{"network", target.first.str()}, {"node", target.second.str()}, {"next_hops", hops}, {"key", wire::hex(pub)},
                {"ip", has_ip ? ip.str() : std::string()}});
        }
        for (const auto& s : end_sessions) result["end_sessions"].push_back({{"network", s.first.first.str()},
            {"node", s.first.second.str()}, {"ready", s.second.confirmed}, {"id", s.second.id}});
        return result;
    }
};

Node::Node(EventLoop& loop, Configure config, std::unique_ptr<PacketDevice> device, NodeOptions options)
    : impl_(new Impl(loop, std::move(config), std::move(device), std::move(options))) {}
Node::~Node() { impl_->stop(); }
void Node::start() { impl_->start(); }
void Node::stop() { reload_resume_ = false; impl_->stop(); }
void Node::reset_links() {
    Impl::Dispatch dispatch(*impl_);
    for (auto& l : impl_->links) impl_->fail(*l);
    if (impl_->address_service) impl_->address_service->reset_links();
}
wire::Json Node::status() const { return impl_->status(); }
wire::Json Node::remote_control(const std::string& request) const { return impl_->remote_control(request); }
const PublicKey& Node::public_key() const { return impl_->key; }
Configure Node::configuration() const { return impl_->config; }
wire::Json Node::apply_config(const Configure& requested) {
    Json result{{"ok", false}, {"mode", "noop"}, {"interrupted", false}, {"rolled_back", false}, {"running", impl_->started}};
    if (reloading_ || impl_->dispatch_depth) { result["error"] = "reload_busy"; return result; }
    struct Guard { bool& value; explicit Guard(bool& flag) : value(flag) { value = true; } ~Guard() { value = false; } } guard(reloading_);
    Configure replacement;
    Json previous_json, next_json;
    try {
        // Validate caller-built objects as strictly as configuration files, and
        // compare normalized forms so peer ordering/default spelling is inert.
        const auto text = serialize_config(requested);
        replacement = parse_config(text); next_json = Json::parse(text);
        previous_json = Json::parse(serialize_config(impl_->config));
    } catch (const std::exception& error) {
        result["error"] = std::string("invalid configuration: ") + error.what(); return result;
    }
    const bool restore_device = impl_->device_failed || reload_resume_;
    if (previous_json == next_json && !restore_device) {
        result["ok"] = true; return result;
    }
    auto previous_base = previous_json, next_base = next_json;
    previous_base.erase("remote_desktop"); next_base.erase("remote_desktop");
    if (previous_base == next_base && !restore_device) {
        impl_->config = std::move(replacement);
        result["ok"] = true; result["mode"] = "remote"; return result;
    }
    previous_base.erase("peers"); next_base.erase("peers");
    if (previous_base == next_base && !restore_device) {
        result["mode"] = "peers";
        std::map<std::string, Json> before, after;
        for (const auto& peer : previous_json.value("peers", Json::array())) before[peer.at("endpoint").get<std::string>()] = peer;
        for (const auto& peer : next_json.value("peers", Json::array())) after[peer.at("endpoint").get<std::string>()] = peer;
        std::set<Endpoint> changed;
        for (const auto& peer : before) if (!after.count(peer.first) || after.at(peer.first) != peer.second) changed.insert(Endpoint::parse(peer.first));
        for (const auto& peer : after) if (!before.count(peer.first) || before.at(peer.first) != peer.second) changed.insert(Endpoint::parse(peer.first));
        for (const auto& link : impl_->links) if (!link->dead && (!link->remote.port || changed.count(link->remote))) result["interrupted"] = true;
        result["changed_peers"] = changed.size();
        const auto previous = impl_->config;
        const bool was_running = impl_->started;
        try {
            impl_->replace_peers(std::move(replacement), changed);
            result["ok"] = true;
        } catch (const std::exception& error) {
            result["error"] = std::string("peer reload failed: ") + error.what();
            try { impl_->replace_peers(previous, changed); result["rolled_back"] = true; }
            catch (const std::exception& rollback) {
                result["rollback_error"] = rollback.what(); impl_->stop(); reload_resume_ = was_running;
            }
        }
        result["running"] = impl_->started; return result;
    }
    result["mode"] = "rebuild";
    const auto previous = impl_->config;
    auto options = impl_->options;
    options.identity = impl_->identity;
    if ((!previous.networks.empty() || !replacement.networks.empty()) && !options.device_factory) {
        result["error"] = "device_factory_required"; return result;
    }
    const bool resume = impl_->started || reload_resume_;
    result["interrupted"] = impl_->started;
    EventLoop& loop = impl_->loop;
    std::unique_ptr<Impl> candidate;
    auto create = [&](const Configure& config) -> std::unique_ptr<Impl> {
        std::unique_ptr<PacketDevice> device;
        if (!config.networks.empty()) {
            device = options.device_factory(config);
            if (!device) throw std::runtime_error("device factory returned no virtual interface");
        }
        Endpoint previous_server;
        if (previous.address_server.enabled && replacement.address_server.enabled &&
                previous.address_server.state_file == replacement.address_server.state_file &&
                previous.address_server.address != replacement.address_server.address)
            previous_server = config.address_server.address == replacement.address_server.address
                ? previous.address_server.address : replacement.address_server.address;
        std::unique_ptr<Impl> value(new Impl(loop, config, std::move(device), options, previous_server));
        try { if (resume) value->start(); }
        catch (...) { value->stop(); throw; }
        return value;
    };
    try {
        // Release the old UDP socket and TUN before opening replacements. Keep
        // the stopped Impl as an inspectable fallback if recovery also fails.
        impl_->stop(); impl_->address_service.reset(); impl_->device.reset();
        candidate = create(replacement);
        impl_.swap(candidate);
        reload_resume_ = false; result["ok"] = true;
    } catch (const std::exception& error) {
        result["error"] = std::string("configuration rebuild failed: ") + error.what();
        candidate.reset();
        try {
            impl_->stop(); impl_->address_service.reset(); impl_->device.reset();
            candidate = create(previous);
            impl_.swap(candidate);
            reload_resume_ = false; result["rolled_back"] = true;
        } catch (const std::exception& rollback) {
            result["rollback_error"] = rollback.what();
            impl_->device_failed = true; impl_->tunnels.clear(); impl_->grants.clear(); reload_resume_ = resume;
        }
    }
    result["running"] = impl_->started; return result;
}
