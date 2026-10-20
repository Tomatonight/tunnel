#include "node.h"
#include "tcp_transport.h"
#include "tls.h"
#include "tunnel.h"
#include <algorithm>
#include <csignal>
#include <iostream>
#include <stdexcept>

namespace {
using Json = wire::Json;
unsigned checks = 0;
std::function<void()> diagnostics;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(std::string("check failed: ") + #x + " line " + std::to_string(__LINE__)); } while (0)

const char* shared_key = "legacy-peer-test-only-secret";
const char* network_cidr = "10.98.0.0/24";

void until(EventLoop& loop, const std::function<bool()>& condition, unsigned timeout = 10000) {
    auto poll = loop.addTimer(std::chrono::milliseconds(10), [&](evutil_socket_t, short) {
        if (condition()) loop.breakLoop();
    }, true);
    auto deadline = loop.addTimer(std::chrono::milliseconds(timeout), [&](evutil_socket_t, short) { loop.breakLoop(); });
    loop.run();
    if (!condition() && diagnostics) diagnostics();
    CHECK(condition());
}

std::vector<Endpoint> ports(EventLoop& loop) {
    std::vector<std::unique_ptr<UdpTransport>> udp;
    std::vector<std::unique_ptr<TcpListener>> tcp;
    std::vector<Endpoint> result;
    for (unsigned i = 0; i < 100 && result.size() != 2; ++i) {
        try {
            auto bind = Endpoint::parse("127.0.0.1:1"); bind.port = 0;
            std::unique_ptr<UdpTransport> u(new UdpTransport(loop, bind, 1472, [](const Endpoint&, Bytes) {}));
            const auto endpoint = u->local_address();
            std::unique_ptr<TcpListener> t(new TcpListener(loop, endpoint, [](evutil_socket_t fd) { evutil_closesocket(fd); }));
            result.push_back(endpoint); udp.push_back(std::move(u)); tcp.push_back(std::move(t));
        } catch (const std::exception&) {}
    }
    if (result.size() != 2) throw std::runtime_error("cannot reserve legacy peer ports");
    return result;
}

Bytes probe(unsigned char kind, std::uint64_t token) {
    Bytes result{kind};
    for (int shift = 56; shift >= 0; shift -= 8) result.push_back(static_cast<unsigned char>(token >> shift));
    return result;
}

Bytes broadcast(unsigned source) {
    Bytes result(100);
    result[0] = 0x45; result[3] = 100; result[8] = 64; result[9] = 17;
    result[12] = result[16] = 10; result[13] = result[17] = 98;
    result[15] = static_cast<unsigned char>(source); result[19] = 255;
    result[20] = 0x10; result[21] = static_cast<unsigned char>(source); result[23] = 42; result[25] = 80;
    result[99] = static_cast<unsigned char>(source); return result;
}

class MemoryDevice : public PacketDevice {
public:
    Receiver receiver;
    std::vector<Bytes> delivered;
    void start(Receiver value) override { receiver = std::move(value); }
    bool send(const Bytes& packet) override { delivered.push_back(packet); return true; }
    std::string name() const override { return "legacy-peer-memory"; }
};

// A deliberately old-v1 server: its Hello has neither transport/tcp_data nor
// dynamic membership capability, it derives the original UDP exporter context,
// and its stream parser accepts only JSON control frames. This does not use
// Node's new negotiation code on the emulated side.
class LegacyPeer {
    struct Connection {
        std::unique_ptr<TlsChannel> tls;
        std::unique_ptr<TcpStream> tcp;
        std::unique_ptr<CryptoSession> crypto;
        wire::Decoder decoder;
        bool sent_hello = false, closed = false, acknowledged = false;
    };
    EventLoop& loop_;
    Endpoint local_, remote_;
    IdentityKey identity_;
    std::vector<std::unique_ptr<Connection>> connections_;
    std::unique_ptr<UdpTransport> udp_;
    std::unique_ptr<TcpListener> listener_;
    void flush(Connection& connection) { connection.tcp->send(connection.tls->drain()); }
    void send_control(Connection& connection, const Json& message) {
        connection.tls->write(wire::frame(message)); flush(connection);
    }
    void process(Connection& connection, const Bytes& bytes) {
        try {
            connection.tls->feed(bytes);
            if (connection.tls->ready() && !connection.sent_hello) {
                connection.sent_hello = true;
                send_control(connection, {{"type", "hello"}, {"version", 1}, {"node", local_.str()},
                    {"key", wire::hex(identity_.public_key())},
                    {"networks", {{{"network", network_cidr}, {"ip", "10.98.0.2"}}}}});
            }
            connection.decoder.append(connection.tls->read());
            Json message;
            while (connection.decoder.next(message)) {
                const auto type = message.at("type").get<std::string>();
                if (type == "hello") {
                    ++hellos;
                    const auto remote_key = wire::key(message.at("key"));
                    const auto local_key = identity_.public_key();
                    std::string context = local_ < remote_ ? local_.str() + "|" + remote_.str() : remote_.str() + "|" + local_.str();
                    context += std::string("|") + network_cidr;
                    context += local_ < remote_ ? "|" + wire::hex(local_key) + "|" + wire::hex(remote_key) :
                        "|" + wire::hex(remote_key) + "|" + wire::hex(local_key);
                    connection.crypto = connection.tls->session(CryptoScope::Link, context);
                    udp_->send(remote_, connection.crypto->seal(probe(4, 0x123456789abcdef0ULL)));
                } else if (type == "ping") send_control(connection, {{"type", "pong"}});
                else if (type != "pong" && type != "sync" && type != "route" && type != "withdraw")
                    throw std::runtime_error("unexpected control at legacy peer");
            }
            flush(connection);
        } catch (const std::exception& error) {
            errors.push_back(error.what()); connection.tcp->close();
        }
    }
    void receive_udp(const Endpoint& from, const Bytes& packet) {
        if (from != remote_) return;
        for (auto& item : connections_) {
            auto& connection = *item;
            if (!connection.crypto || connection.closed) continue;
            Bytes plain;
            if (!connection.crypto->open(packet, plain)) continue;
            if (plain.size() == 9 && plain[0] == 4) {
                ++challenges; plain[0] = 5; udp_->send(remote_, connection.crypto->seal(plain));
                // Our initial UDP challenge can arrive before the remote has
                // consumed the TLS Hello. Like a real legacy heartbeat, retry
                // the same outstanding token instead of assuming delivery.
                if (!connection.acknowledged)
                    udp_->send(remote_, connection.crypto->seal(probe(4, 0x123456789abcdef0ULL)));
            } else if (plain == probe(5, 0x123456789abcdef0ULL)) {
                if (!connection.acknowledged) ++acknowledgements;
                connection.acknowledged = true;
            }
            else {
                protocol::ForwardHeader header; Bytes payload;
                if (protocol::decode(plain, &header, &payload)) received.push_back(payload);
                else errors.push_back("invalid legacy UDP forwarding packet");
            }
            return;
        }
    }
    Connection& live() {
        for (auto& connection : connections_) if (!connection->closed && connection->crypto) return *connection;
        throw std::runtime_error("legacy connection unavailable");
    }
public:
    unsigned hellos = 0, challenges = 0, acknowledgements = 0, closed = 0;
    std::vector<std::string> errors;
    std::vector<Bytes> received;
    LegacyPeer(EventLoop& loop, Endpoint local, Endpoint remote) : loop_(loop), local_(local), remote_(remote) {
        udp_.reset(new UdpTransport(loop, local_, 1472, [this](const Endpoint& from, Bytes packet) { receive_udp(from, packet); }));
        listener_.reset(new TcpListener(loop, local_, [this](evutil_socket_t fd) {
            std::unique_ptr<Connection> connection(new Connection); auto* pointer = connection.get();
            pointer->tls.reset(new TlsChannel(false, "", [this](const std::string& identity) {
                return identity == remote_.str() + "|" + local_.str() ? std::string(shared_key) : std::string();
            }));
            connections_.push_back(std::move(connection));
            pointer->tcp.reset(new TcpStream(loop_, fd, {}, [this, pointer](const Bytes& bytes) { process(*pointer, bytes); },
                [] {}, [this, pointer] { pointer->closed = true; ++closed; }));
        }));
    }
    void send_broadcast(const Bytes& packet) {
        NetworkConfig config; config.tunnel = Network::parse(network_cidr); config.tunnel_ip = IpAddress::parse("10.98.0.2");
        PacketInfo info; CHECK(Tunnel(config, 1280).inspect(packet, &info, true));
        protocol::ForwardHeader header; header.network = config.tunnel; header.source = local_;
        header.kind = info.kind; header.flow_id = info.flow_id;
        CHECK(udp_->send(remote_, live().crypto->seal(protocol::encode(header, packet))));
    }
    void send_unnegotiated_binary() {
        auto& connection = live();
        connection.tls->write(wire::data_frame(connection.crypto->seal(probe(4, 7)))); flush(connection);
    }
};

Configure config(const Endpoint& local, const Endpoint& remote, const char* transport) {
    return parse_config(Json{{"address", local.str()}, {"networks", {"10.98.0.1/24"}},
        {"listen", {{"bind_address", local.str()}}},
        {"peers", {{{"address", remote.str()}, {"shared_key", shared_key}, {"transport", transport}}}}}.dump());
}

std::uint64_t counter(const Node& node, const char* name) {
    return node.status().at("counters").value(name, std::uint64_t(0));
}

void legacy_tests(bool request_tcp) {
    EventLoop loop; const auto endpoints = ports(loop);
    LegacyPeer legacy(loop, endpoints[1], endpoints[0]);
    std::vector<std::string> logs;
    NodeOptions options; options.tick_ms = 10; options.heartbeat_ms = 300;
    options.failure_timeout_ms = 5000; options.reconnect_ms = 10000;
    options.log = [&](const std::string& message) { logs.push_back(message); };
    auto* device = new MemoryDevice;
    Node node(loop, config(endpoints[0], endpoints[1], request_tcp ? "tcp" : "udp"), std::unique_ptr<PacketDevice>(device), options);
    diagnostics = [&] {
        std::cerr << "legacy request_tcp=" << request_tcp << " hellos=" << legacy.hellos << " challenges=" << legacy.challenges
            << " acknowledgements=" << legacy.acknowledgements << " closed=" << legacy.closed << '\n' << node.status().dump(2) << '\n';
        for (const auto& message : logs) std::cerr << message << '\n';
        for (const auto& error : legacy.errors) std::cerr << "legacy error: " << error << '\n';
    };
    node.start();
    if (request_tcp) {
        until(loop, [&] { return legacy.hellos && counter(node, "control_rejected") && legacy.closed; });
        CHECK(counter(node, "peer_up") == 0);
        CHECK(node.status().at("routes").empty());
        CHECK(counter(node, "tcp_data_sent") == 0 && counter(node, "udp_data_sent") == 0);
        CHECK(std::any_of(logs.begin(), logs.end(), [](const std::string& message) {
            return message.find("does not support TCP data encapsulation") != std::string::npos;
        }));
    } else {
        until(loop, [&] { return counter(node, "peer_up") == 1 && legacy.challenges >= 2 && legacy.acknowledgements == 1; });
        CHECK(!node.status().at("routes").empty());
        CHECK(node.status().at("peers")[0].at("transport") == "udp");
        CHECK(legacy.errors.empty());
        const auto to_legacy = broadcast(1); CHECK(static_cast<bool>(device->receiver)); device->receiver(to_legacy);
        until(loop, [&] { return !legacy.received.empty(); });
        CHECK(legacy.received.back() == to_legacy);
        const auto from_legacy = broadcast(2); legacy.send_broadcast(from_legacy);
        until(loop, [&] { return !device->delivered.empty(); });
        CHECK(device->delivered.back() == from_legacy);
        CHECK(counter(node, "tcp_data_sent") == 0 && counter(node, "tcp_data_received") == 0);
        // Valid TLS and link AEAD are insufficient to send binary frames when
        // the negotiated data channel is UDP. The new node must close it.
        legacy.send_unnegotiated_binary();
        until(loop, [&] { return counter(node, "tcp_data_rejected") == 1 && legacy.closed; });
        CHECK(node.status().at("routes").empty());
        CHECK(counter(node, "peer_down") == 1);
        CHECK(std::any_of(logs.begin(), logs.end(), [](const std::string& message) {
            return message.find("TCP data was not negotiated") != std::string::npos;
        }));
    }
    CHECK(legacy.errors.empty());
    node.stop();
    diagnostics = {};
}
}

int main() {
    try {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        SocketSystem sockets;
        legacy_tests(false); legacy_tests(true);
        std::cout << "Passed " << checks << " legacy transport compatibility checks\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
