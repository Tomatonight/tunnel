#pragma once
#include "device.h"
#include "udp_transport.h"
#include "wire.h"
struct NodeOptions {
    unsigned tick_ms = 50;
    unsigned heartbeat_ms = 5000;
    unsigned failure_timeout_ms = 20000;
    unsigned handshake_timeout_ms = 10000;
    unsigned reconnect_ms = 1000;
    unsigned session_lifetime_ms = 3600000;
    unsigned address_proof_lifetime_ms = 60000;
    UdpTransport::Protector protect;
    std::shared_ptr<IdentityKey> identity; // Optional host-owned process identity (Android service restarts).
    std::function<void(const std::string&)> log;
    // Called on the protocol thread after the previous device is destroyed.
    // Must create a fresh device for the complete new configuration or throw.
    std::function<std::unique_ptr<PacketDevice>(const Configure&)> device_factory;
};
class Node {
public:
    Node(EventLoop&, Configure, std::unique_ptr<PacketDevice>, NodeOptions = {});
    ~Node();
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;
    void start();
    void stop();
    void reset_links(); // Called on the protocol thread after a network change.
    // Call from the host's protocol-thread control handler, outside Node callbacks.
    // Complex changes interrupt links and recreate resources, preserving identity.
    // Failure returns ok:false and attempts to restore the previous configuration.
    wire::Json apply_config(const Configure&);
    Configure configuration() const; // Value copy remains valid across reloads.
    wire::Json status() const;
    // Trusted local parent pipe only; never expose this signing bridge as a
    // network service. Includes bounded JSON parsing and structured errors.
    wire::Json remote_control(const std::string& request) const;
    const PublicKey& public_key() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    bool reloading_ = false;
    bool reload_resume_ = false;
};
