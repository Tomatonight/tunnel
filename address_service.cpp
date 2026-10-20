#include "address_service.h"
#include "tls.h"
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <map>
#include <limits>
#include <set>
#include <sstream>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace {
using Json = wire::Json;
using Clock = std::chrono::steady_clock;
using Time = Clock::time_point;
using LeaseKey = std::pair<Network, Endpoint>;
constexpr std::size_t max_server_clients = 256;
constexpr std::size_t max_pending_server_clients = 64;
std::uint64_t wall_ms() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
std::uint64_t age(Time now, Time before) { return std::chrono::duration_cast<std::chrono::milliseconds>(now - before).count(); }
std::uint64_t timestamp(const Json& value) {
    if (!value.is_number_integer() || value < 0) throw std::invalid_argument("invalid lease timestamp");
    return value.get<std::uint64_t>();
}
Bytes signed_body(const Json& body) {
    const auto text = std::string("tunnel-address-grant-v1\n") + body.dump();
    return Bytes(text.begin(), text.end());
}
bool increment(IpAddress& ip) {
    for (int i = ip.family == 4 ? 3 : 15; i >= 0; --i) if (++ip.bytes[static_cast<std::size_t>(i)]) return true;
    return false;
}
struct FileLock {
#ifdef _WIN32
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~FileLock() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
#else
    int fd = -1;
    ~FileLock() { if (fd >= 0) close(fd); }
#endif
    void acquire(const std::string& path) {
#ifdef _WIN32
        handle = CreateFileA((path + ".lock").c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("address lease database is locked or inaccessible");
#else
        fd = open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB)) throw std::runtime_error("address lease database is locked or inaccessible");
#endif
    }
};
void atomic_write(const std::string& path, const std::string& text) {
    const auto temp = path + ".tmp";
#ifdef _WIN32
    HANDLE file = CreateFileA(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot write address lease database");
    DWORD written = 0;
    const bool okay = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) && written == text.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!okay || !MoveFileExA(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("cannot commit address lease database");
#else
    const int fd = open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) throw std::runtime_error("cannot write address lease database");
    std::size_t offset = 0; bool okay = true;
    while (offset < text.size()) {
        const auto count = write(fd, text.data() + offset, text.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { okay = false; break; }
        offset += static_cast<std::size_t>(count);
    }
    if (fsync(fd)) okay = false;
    close(fd);
    if (!okay || std::rename(temp.c_str(), path.c_str())) throw std::runtime_error("cannot commit address lease database");
    const auto slash = path.find_last_of('/');
    const auto directory = slash == std::string::npos ? "." : (slash ? path.substr(0, slash) : "/");
    const int dir = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) throw std::runtime_error("cannot sync address lease database directory");
    const bool synced = fsync(dir) == 0; close(dir);
    if (!synced) throw std::runtime_error("cannot sync address lease database directory");
#endif
}
}

struct AddressService::Impl {
    struct Lease { IpAddress ip; std::uint64_t offline_at = 0, proof_until = 0; bool online = false; };
    struct Channel {
        bool client = false, dead = false, hello = false, ready = false;
        Endpoint remote;
        const AddressClientConfig* config = nullptr;
        std::unique_ptr<TcpStream> tcp;
        std::unique_ptr<TlsChannel> tls;
        wire::Decoder decoder;
        PublicKey authority{};
        std::vector<Network> requested;
        std::map<Network, Grant> grants;
        Json errors = Json::array();
        Time created = Clock::now(), activity = created, heartbeat = Time{};
    };
    EventLoop& loop;
    Configure config;
    Callback callback;
    Options options;
    bool running = false, server_running = false;
    std::string server_error;
    std::unique_ptr<IdentityKey> identity;
    std::unique_ptr<FileLock> lock;
    std::unique_ptr<TcpListener> listener;
    EventLoop::Handle timer;
    std::vector<std::unique_ptr<Channel>> channels;
    std::map<Endpoint, Channel*> clients, accepted;
    std::map<Endpoint, Time> retry;
    std::map<Endpoint, std::string> client_errors;
    std::map<LeaseKey, Lease> leases;

    Impl(EventLoop& l, const Configure& c, Callback cb, const Options& o) : loop(l), config(c), callback(std::move(cb)), options(o) {
        if (!config.address_server.shared_key.empty() && !config.address_server.clients.empty())
            throw std::invalid_argument("address server authentication modes are mutually exclusive");
        if (!options.tick_ms || !options.heartbeat_ms || options.failure_timeout_ms <= options.heartbeat_ms ||
            !options.handshake_timeout_ms || !options.reconnect_ms || options.proof_lifetime_ms <= options.heartbeat_ms)
            throw std::invalid_argument("invalid address service timer options");
    }
    void log(const std::string& text) { if (options.log) try { options.log("address service: " + text); } catch (...) {} }
    void notify(const Network& n, const Grant* g) { if (callback) callback(n, g); }
    std::uint64_t reclaim_deadline(const Lease& lease) const {
        const auto delay = std::uint64_t(config.address_server.reclaim_after) * 1000;
        const auto maximum = std::numeric_limits<std::uint64_t>::max();
        const auto offline_deadline = lease.offline_at > maximum - delay ? maximum : lease.offline_at + delay;
        return std::max(lease.proof_until, offline_deadline);
    }
    const AddressClientConfig* authorized(const Endpoint& e) const {
        for (const auto& c : config.address_server.clients) if (c.address == e) return &c;
        return nullptr;
    }
    void save() {
        Json value = {{"version", 1}, {"server", config.address_server.address.str()}, {"leases", Json::array()}};
        for (const auto& item : leases) value["leases"].push_back({{"network", item.first.first.str()}, {"node", item.first.second.str()},
            {"ip", item.second.ip.str()}, {"offline_at", item.second.offline_at}, {"proof_until", item.second.proof_until}});
        atomic_write(config.address_server.state_file, value.dump(2) + '\n');
    }
    void load() {
        leases.clear();
        lock.reset(new FileLock); lock->acquire(config.address_server.state_file);
        std::ifstream file(config.address_server.state_file.c_str(), std::ios::binary);
        if (file) {
            std::string text; char block[4096];
            while (file.read(block, sizeof(block)) || file.gcount()) {
                text.append(block, static_cast<std::size_t>(file.gcount()));
                if (text.size() > 16 * 1024 * 1024) throw std::runtime_error("address lease database too large");
            }
            if (file.bad()) throw std::runtime_error("cannot read address lease database");
            std::vector<std::set<std::string>> keys;
            const auto value = Json::parse(text, [&](int depth, Json::parse_event_t event, Json& value) {
                if (depth > 8) throw std::runtime_error("address lease database nesting exceeds 8 levels");
                if (event == Json::parse_event_t::object_start) keys.emplace_back();
                else if (event == Json::parse_event_t::key && !keys.back().insert(value.get<std::string>()).second)
                    throw std::runtime_error("duplicate address lease database field");
                else if (event == Json::parse_event_t::object_end) keys.pop_back();
                return true;
            });
            const bool same_server = value.at("server") == config.address_server.address.str() ||
                (options.previous_server.port && value.at("server") == options.previous_server.str());
            if (value.at("version") != 1 || !same_server ||
                !value.at("leases").is_array() || value.at("leases").size() > 16384) throw std::runtime_error("invalid address lease database");
            std::set<IpAddress> occupied;
            for (const auto& entry : value.at("leases")) {
                LeaseKey key{Network::parse(entry.at("network").get<std::string>()), Endpoint::parse(entry.at("node").get<std::string>())};
                Lease lease; lease.ip = IpAddress::parse(entry.at("ip").get<std::string>());
                lease.offline_at = timestamp(entry.at("offline_at")); lease.proof_until = timestamp(entry.at("proof_until"));
                if (lease.offline_at > std::numeric_limits<std::uint64_t>::max() - std::uint64_t(config.address_server.reclaim_after) * 1000)
                    throw std::runtime_error("invalid persisted offline timestamp");
                // Retain reservations for removed pools/nodes until their old
                // proofs and reclaim hold expire; admission is checked later.
                if (entry.at("network") != key.first.str() || !key.first.usable_host(lease.ip) || !key.second.ip.unicast() ||
                    !occupied.insert(lease.ip).second || leases.count(key))
                    throw std::runtime_error("invalid or conflicting persisted address lease");
                if (!lease.offline_at) lease.offline_at = wall_ms();
                leases.emplace(key, lease);
            }
        } else {
#ifdef _WIN32
            const auto attrs = GetFileAttributesA(config.address_server.state_file.c_str());
            const auto error = GetLastError();
            if (attrs != INVALID_FILE_ATTRIBUTES || (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND))
#else
            if (access(config.address_server.state_file.c_str(), F_OK) == 0 || errno != ENOENT)
#endif
                throw std::runtime_error("cannot read existing address lease database");
        }
        // Windows CRT streams do not share deletion; release the read handle
        // before atomically replacing this same path below.
        file.close();
        save(); // Prove persistence is writable before accepting any allocation.
    }
    void fatal(const std::string& error) {
        server_error = error; server_running = false; listener.reset(); log(error);
        for (auto& channel : channels) if (!channel->client) close(*channel, "lease storage unavailable", false);
    }
    void close(Channel& c, const std::string& error, bool persist = true) {
        if (c.dead) return;
        c.dead = true;
        if (c.tcp) c.tcp->close();
        if (c.client) {
            if (clients.count(c.remote) && clients[c.remote] == &c) clients.erase(c.remote);
            client_errors[c.remote] = error; retry[c.remote] = Clock::now() + std::chrono::milliseconds(options.reconnect_ms);
            auto old = std::move(c.grants); c.grants.clear(); c.ready = false;
            for (const auto& item : old) notify(item.first, nullptr);
        } else if (accepted.count(c.remote) && accepted[c.remote] == &c) {
            accepted.erase(c.remote);
            for (auto& item : leases) if (item.first.second == c.remote && item.second.online) {
                item.second.online = false; item.second.offline_at = wall_ms();
            }
            if (persist && server_running) try { save(); } catch (const std::exception& e) { fatal(e.what()); }
        }
        c.ready = false;
    }
    void flush(Channel& c) { if (!c.dead && !c.tcp->send(c.tls->drain())) close(c, "TCP send failed"); }
    void send(Channel& c, const Json& message) {
        if (c.dead) return;
        try { c.tls->write(wire::frame(message)); flush(c); }
        catch (...) { close(c, "encrypted control send failed"); }
    }
    void make(bool client, const AddressClientConfig* setting, evutil_socket_t fd = EVUTIL_INVALID_SOCKET) {
        std::unique_ptr<Channel> object(new Channel); auto* c = object.get(); c->client = client; c->config = setting;
        if (client) c->remote = setting->address;
        channels.push_back(std::move(object));
        try {
            if (client) {
                const auto id = "allocation-v1|" + config.listen.address.str() + "|" + c->remote.str();
                c->tls.reset(new TlsChannel(true, id, [setting](const std::string&) { return setting->shared_key; }));
                clients[c->remote] = c;
            } else c->tls.reset(new TlsChannel(false, "", [this, c](const std::string& id) {
                const std::string prefix = "allocation-v1|";
                if (id.compare(0, prefix.size(), prefix)) return std::string();
                const auto separator = id.find('|', prefix.size());
                if (separator == std::string::npos || id.substr(separator + 1) != config.address_server.address.str()) return std::string();
                try {
                    const auto remote = Endpoint::parse(id.substr(prefix.size(), separator - prefix.size()));
                    if (!remote.ip.unicast()) return std::string();
                    if (!config.address_server.shared_key.empty()) {
                        c->remote = remote;
                        return config.address_server.shared_key;
                    }
                    const auto* cfg = authorized(remote); if (!cfg) return std::string();
                    c->remote = remote; c->config = cfg; return cfg->shared_key;
                } catch (...) { return std::string(); }
            }));
            const auto accepted_fd = fd;
            fd = EVUTIL_INVALID_SOCKET; // TcpStream owns accepted_fd, including construction failure.
            c->tcp.reset(new TcpStream(loop, accepted_fd, options.protect,
                [this, c](const Bytes& bytes) { receive(*c, bytes); },
                [this, c] { try { c->tls->advance(); flush(*c); } catch (...) { close(*c, "TLS handshake failed"); } },
                [this, c] { close(*c, "server disconnected or authentication failed"); }));
            if (client) c->tcp->connect(setting->address);
        } catch (...) { if (fd != EVUTIL_INVALID_SOCKET) evutil_closesocket(fd); close(*c, "connection setup failed"); }
    }
    bool validate(const Endpoint& peer, const Network& network, const Endpoint& server, const PublicKey& key,
                  const Json& proof, IpAddress* output) const {
        try {
            if (!proof.is_object() || proof.size() != 2) return false;
            const auto& body = proof.at("body");
            if (!body.is_object() || body.size() != 5 || body.at("server") != server.str() || body.at("node") != peer.str() || body.at("network") != network.str()) return false;
            const auto expiry = timestamp(body.at("expires_at")), now = wall_ms();
            if (expiry <= now || expiry > now + options.proof_lifetime_ms + 5000) return false;
            const auto ip = IpAddress::parse(body.at("ip").get<std::string>());
            if (!network.usable_host(ip) || !IdentityKey::verify(key, signed_body(body), wire::unhex(proof.at("signature").get<std::string>(), 64))) return false;
            if (output) *output = ip;
            return true;
        } catch (...) { return false; }
    }
    bool allocate(const LeaseKey& key, IpAddress* address) {
        auto existing = leases.find(key);
        if (existing != leases.end()) { *address = existing->second.ip; return true; }
        if (leases.size() >= 16384) return false;
        auto candidate = key.first.address;
        // Skip the IPv4 network address where required; IPv6 starts at ::1.
        if (candidate.family == 4 && candidate.bytes[0] == 0) { candidate.bytes.fill(0); candidate.bytes[0] = 1; }
        else if ((candidate.family == 4 && key.first.prefix < 31) || (candidate.family == 6 && key.first.prefix < 128)) increment(candidate);
        std::set<IpAddress> occupied;
        for (const auto& item : leases) occupied.insert(item.second.ip);
        for (std::size_t count = 0; count < leases.size() + 3 && key.first.contains(candidate); ++count) {
            if (!occupied.count(candidate) && key.first.usable_host(candidate)) { Lease lease; lease.ip = candidate; leases.emplace(key, lease); *address = candidate; return true; }
            if (!increment(candidate)) break;
        }
        return false;
    }
    void renew(Channel& c) {
        if (!server_running || c.dead) return;
        Json grants = Json::array(), errors = Json::array();
        const auto expiry = wall_ms() + options.proof_lifetime_ms;
        for (const auto& n : c.requested) {
            IpAddress ip; const LeaseKey target{n, c.remote};
            if (!allocate(target, &ip)) { errors.push_back({{"network", n.str()}, {"error", "address pool exhausted"}}); continue; }
            auto& lease = leases.at(target); lease.online = true; lease.offline_at = 0;
            // A small clock-skew guard also prevents reclaim before old tokens die.
            lease.proof_until = std::max(lease.proof_until, expiry + 5000);
            Json body = {{"server", config.address_server.address.str()}, {"node", c.remote.str()},
                {"network", n.str()}, {"ip", ip.str()}, {"expires_at", expiry}};
            Json proof = {{"body", body}, {"signature", wire::hex(identity->sign(signed_body(body)))}};
            if (!validate(c.remote, n, config.address_server.address, identity->public_key(), proof, nullptr)) { fatal("cannot validate generated address proof"); return; }
            grants.push_back(proof);
        }
        try { save(); } catch (const std::exception& e) { fatal(e.what()); return; }
        send(c, {{"type", "leases"}, {"grants", grants}, {"errors", errors}}); c.heartbeat = Clock::now();
    }
    void message(Channel& c, const Json& j) {
        c.activity = Clock::now();
        const auto type = j.at("type").get<std::string>();
        if (type == "ping") { send(c, {{"type", "pong"}}); return; }
        if (type == "pong") return;
        if (c.client && type == "welcome") {
            if (c.hello || j.at("server") != c.remote.str()) throw std::invalid_argument("invalid allocator welcome");
            c.authority = wire::key(j.at("key")); c.hello = true;
            Json nets = Json::array(); for (const auto& n : c.config->networks) nets.push_back(n.str());
            send(c, {{"type", "request"}, {"node", config.listen.address.str()}, {"networks", nets}}); return;
        }
        if (!c.client && type == "request") {
            if (c.ready || !c.remote.port || (!c.config && config.address_server.shared_key.empty()) || j.at("node") != c.remote.str())
                throw std::invalid_argument("invalid allocation request");
            const auto& list = j.at("networks");
            if (!list.is_array() || list.empty() || list.size() > 64) throw std::invalid_argument("invalid pool request");
            const auto& permitted = config.address_server.shared_key.empty() ? c.config->networks : config.address_server.networks;
            std::set<Network> seen;
            for (const auto& value : list) {
                const auto n = Network::parse(value.get<std::string>());
                if (std::find(permitted.begin(), permitted.end(), n) == permitted.end() || !seen.insert(n).second)
                    throw std::invalid_argument("pool is not authorized");
                c.requested.push_back(n);
            }
            if (accepted.count(c.remote)) throw std::invalid_argument("node already has an allocation connection");
            if (accepted.size() >= max_server_clients) throw std::invalid_argument("address server client capacity reached");
            accepted[c.remote] = &c; c.ready = true; renew(c); return;
        }
        if (c.client && c.hello && type == "leases") {
            if (!j.at("grants").is_array() || !j.at("errors").is_array() || j["grants"].size() + j["errors"].size() != c.config->networks.size())
                throw std::invalid_argument("incomplete allocation response");
            std::map<Network, Grant> next; std::set<Network> seen;
            for (const auto& proof : j.at("grants")) {
                const auto n = Network::parse(proof.at("body").at("network").get<std::string>());
                Grant g; g.network = n; g.server = c.remote; g.proof = proof;
                if (std::find(c.config->networks.begin(), c.config->networks.end(), n) == c.config->networks.end() || !seen.insert(n).second ||
                    !validate(config.listen.address, n, c.remote, c.authority, proof, &g.ip))
                    throw std::invalid_argument("invalid lease proof, expired lease, or clock skew");
                next.emplace(n, g);
            }
            for (const auto& error : j.at("errors")) {
                const auto n = Network::parse(error.at("network").get<std::string>());
                if (!error.at("error").is_string() || error.at("error").get<std::string>().size() > 256 ||
                    std::find(c.config->networks.begin(), c.config->networks.end(), n) == c.config->networks.end() || !seen.insert(n).second)
                    throw std::invalid_argument("invalid pool error");
            }
            const auto old = c.grants; c.grants = std::move(next); c.errors = j.at("errors"); c.ready = true; client_errors[c.remote].clear();
            for (const auto& item : old) if (!c.grants.count(item.first)) notify(item.first, nullptr);
            for (const auto& item : c.grants) notify(item.first, &item.second);
            return;
        }
        throw std::invalid_argument("unexpected allocation message");
    }
    void receive(Channel& c, const Bytes& bytes) {
        if (c.dead) return;
        try {
            c.tls->feed(bytes);
            if (!c.client && c.tls->ready() && !c.hello) {
                c.hello = true; send(c, {{"type", "welcome"}, {"server", config.address_server.address.str()}, {"key", wire::hex(identity->public_key())}});
            }
            c.decoder.append(c.tls->read()); Json j; unsigned count = 0;
            while (!c.dead && c.decoder.next(j)) { if (++count > 128) throw std::invalid_argument("too many allocation messages"); message(c, j); }
            flush(c);
        } catch (const std::exception& e) { close(c, e.what()); }
    }
    void tick() {
        if (!running) return;
        const auto now = Clock::now();
        for (auto& c : channels) if (!c->dead) {
            if ((!c->ready && age(now, c->created) >= options.handshake_timeout_ms) || age(now, c->activity) >= options.failure_timeout_ms) {
                close(*c, "allocation connection timeout"); continue;
            }
            if (c->client && c->ready) {
                bool expired = false;
                for (const auto& item : c->grants) if (timestamp(item.second.proof.at("body").at("expires_at")) <= wall_ms()) expired = true;
                if (expired) { close(*c, "lease expired or local clock changed"); continue; }
            }
            if (c->ready && age(now, c->heartbeat) >= options.heartbeat_ms) {
                if (c->client) { send(*c, {{"type", "ping"}}); c->heartbeat = now; }
                else renew(*c);
            }
        }
        channels.erase(std::remove_if(channels.begin(), channels.end(), [](const std::unique_ptr<Channel>& c) { return c->dead; }), channels.end());
        if (server_running) {
            bool changed = false; const auto wall = wall_ms();
            for (auto it = leases.begin(); it != leases.end();) {
                const auto deadline = reclaim_deadline(it->second);
                if (!it->second.online && it->second.offline_at && wall >= deadline) { it = leases.erase(it); changed = true; } else ++it;
            }
            if (changed) try { save(); } catch (const std::exception& e) { fatal(e.what()); }
        }
        for (const auto& c : config.address_clients) if (!clients.count(c.address) && (!retry.count(c.address) || retry[c.address] <= now)) make(true, &c);
    }
    void start() {
        if (running) return;
        server_error.clear(); retry.clear(); client_errors.clear();
        try {
        if (config.address_server.enabled) {
            load(); identity.reset(new IdentityKey);
            listener.reset(new TcpListener(loop, config.address_server.bind_address, [this](evutil_socket_t fd) {
                // Count deferred dead channels too, bounding churn before the
                // next timer cleanup, independently of the configured ACL size.
                const auto inbound = static_cast<std::size_t>(std::count_if(channels.begin(), channels.end(),
                    [](const std::unique_ptr<Channel>& c) { return !c->client; }));
                if (!server_running || inbound >= max_server_clients + max_pending_server_clients ||
                    inbound >= accepted.size() + max_pending_server_clients) { evutil_closesocket(fd); return; }
                make(false, nullptr, fd);
            }, options.protect));
            server_running = true;
        }
        running = true;
        timer = loop.addTimer(std::chrono::milliseconds(options.tick_ms), [this](evutil_socket_t, short) { tick(); }, true);
        if (!timer) throw std::runtime_error("cannot allocate address service timer");
        tick();
        } catch (...) { stop(); lock.reset(); identity.reset(); throw; }
    }
    void stop() {
        running = false; timer.reset(); listener.reset();
        for (auto& c : channels) close(*c, "address service stopped");
        channels.clear(); clients.clear(); accepted.clear(); server_running = false;
        lock.reset(); identity.reset();
    }
    bool verify(const Endpoint& peer, const Network& network, const Json& proof, IpAddress* ip) const {
        for (const auto& c : config.address_clients) if (std::find(c.networks.begin(), c.networks.end(), network) != c.networks.end()) {
            const auto it = clients.find(c.address);
            return it != clients.end() && !it->second->dead && it->second->ready && it->second->grants.count(network) &&
                validate(config.listen.address, network, c.address, it->second->authority, it->second->grants.at(network).proof, nullptr) &&
                validate(peer, network, c.address, it->second->authority, proof, ip);
        }
        return false;
    }
    Json status() const {
        Json server = {{"enabled", config.address_server.enabled}, {"running", server_running}, {"error", server_error}, {"leases", Json::array()}};
        if (config.address_server.enabled) server["address"] = config.address_server.address.str();
        for (const auto& item : leases) server["leases"].push_back({{"node", item.first.second.str()}, {"network", item.first.first.str()},
            {"ip", item.second.ip.str()}, {"online", item.second.online}, {"reclaim_at", item.second.online ? 0 : reclaim_deadline(item.second)}});
        Json result = {{"running", running}, {"server", server}, {"clients", Json::array()}};
        for (const auto& cfg : config.address_clients) {
            const auto found = clients.find(cfg.address); const auto error = client_errors.find(cfg.address);
            Json c = {{"server", cfg.address.str()}, {"state", error != client_errors.end() && !error->second.empty() ? "error" : "waiting"},
                      {"error", error == client_errors.end() ? "" : error->second}, {"grants", Json::array()}, {"errors", Json::array()}};
            if (found != clients.end()) {
                const auto& channel = *found->second; c["state"] = channel.ready ? "connected" : "connecting"; c["errors"] = channel.errors;
                for (const auto& item : channel.grants) c["grants"].push_back({{"network", item.first.str()}, {"ip", item.second.ip.str()}, {"expires_at", item.second.proof.at("body").at("expires_at")}});
            }
            result["clients"].push_back(c);
        }
        return result;
    }
};
AddressService::AddressService(EventLoop& l, const Configure& c, Callback cb, const Options& o) : impl_(new Impl(l, c, std::move(cb), o)) {}
AddressService::~AddressService() { impl_->stop(); }
void AddressService::start() { impl_->start(); }
void AddressService::stop() { impl_->stop(); }
void AddressService::reset_links() { for (auto& c : impl_->channels) if (c->client) impl_->close(*c, "network changed"); }
wire::Json AddressService::status() const { return impl_->status(); }
bool AddressService::verify_grant(const Endpoint& p, const Network& n, const wire::Json& proof, IpAddress* ip) const { return impl_->verify(p, n, proof, ip); }
