#pragma once
#include "parse_config.h"
#include "tcp_transport.h"
#include "wire.h"
#include <functional>
#include <memory>

class AddressService {
public:
    struct Grant {
        Network network;
        IpAddress ip;
        Endpoint server;
        wire::Json proof;
    };
    struct Options {
        unsigned tick_ms = 100;
        unsigned heartbeat_ms = 5000;
        unsigned failure_timeout_ms = 20000;
        unsigned handshake_timeout_ms = 10000;
        unsigned reconnect_ms = 1000;
        unsigned proof_lifetime_ms = 60000;
        // Only a live, explicitly requested configuration reload may migrate a
        // lease database from this previous advertised address. Normal startup
        // leaves it empty and still rejects a database owned by another server.
        Endpoint previous_server;
        UdpTransport::Protector protect;
        std::function<void(const std::string&)> log;
    };
    using Callback = std::function<void(const Network&, const Grant*)>;
    // Callback pointers are borrowed for the duration of the call; null means loss.
    AddressService(EventLoop&, const Configure&, Callback, const Options&);
    ~AddressService();
    AddressService(const AddressService&) = delete;
    AddressService& operator=(const AddressService&) = delete;
    void start();
    void stop();
    void reset_links();
    wire::Json status() const;
    // Requires a live authenticated connection to this network's allocator.
    bool verify_grant(const Endpoint& peer, const Network&, const wire::Json& proof, IpAddress* verified_ip = nullptr) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
