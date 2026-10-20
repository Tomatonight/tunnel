#pragma once
#include "address.h"
#include <stdexcept>
#include <string>
#include <vector>

struct NetworkConfig {
    Network tunnel;
    IpAddress tunnel_ip;
    Endpoint allocation_server; // port == 0: static; otherwise IP awaits an authenticated grant.
};
struct AddressClientConfig {
    Endpoint address;
    std::string shared_key;
    std::vector<Network> networks;
};
struct AddressServerConfig {
    bool enabled = false;
    Endpoint address;
    Endpoint bind_address;
    std::string state_file = "address-leases.json";
    unsigned reclaim_after = 86400;
    std::vector<Network> networks;
    std::vector<AddressClientConfig> clients;
    // Nonempty: shared admission key; empty: explicit per-node clients mode.
    std::string shared_key;
};
struct PeerConfig {
    Endpoint address;
    std::string shared_key;
    std::vector<NetworkConfig> networks;
    // Data encapsulation for this adjacency; control traffic always uses TLS/TCP.
    std::string transport = "udp";
};
struct ListenConfig {
    bool enabled = false;
    Endpoint address;
    Endpoint bind_address;
    std::vector<NetworkConfig> networks;
};
struct AdvertisedRoute {
    Network tunnel;
    Network prefix;
    bool snat = false;
};
struct RemoteDesktopConfig {
    // Preserve an explicitly disabled block when saving through the GUI.
    bool configured = false;
    bool enabled = false;
    std::vector<Network> networks;
    std::string access = "authorized_devices";
    bool unattended = false;
    unsigned port = 47831;
    std::string device_name;
};
// A canonical, non-default CIDR whose complete range is unicast.
bool valid_advertised_prefix(const Network&);
inline const char* default_device_backend() {
#if defined(__linux__) && !defined(__ANDROID__)
    return "kernel";
#else
    return "tun";
#endif
}
struct Configure {
    unsigned tun_mtu = 1280;
    unsigned transport_mtu = 1500;
    ListenConfig listen;
    std::vector<PeerConfig> peers;
    std::vector<NetworkConfig> networks;
    AddressServerConfig address_server;
    std::vector<AddressClientConfig> address_clients;
    std::vector<AdvertisedRoute> advertise_routes;
    RemoteDesktopConfig remote_desktop;
    // Linux defaults to its kernel net_device; Android and other platforms use TUN.
    std::string device_backend = default_device_backend();
};
using Config = Configure;
extern Config g_config;
class config_error : public std::runtime_error {
public:
    explicit config_error(const std::string& message) : std::runtime_error(message) {}
};
Configure parse_config(const std::string& text);
Configure parse_config_file(const std::string& path);
// Emit the simplified schema, preserving the exact network authorization sets.
// Configuration text contains peer secrets; callers must store it privately.
std::string serialize_config(const Configure& config);
Configure load_config(const std::string& path);
bool try_parse_config(const std::string& text, Configure* result, std::string* error = nullptr);
