#pragma once
#include "parse_config.h"
#include "protocol.h"
#include <vector>

struct PacketInfo {
    IpAddress source, destination;
    protocol::PacketKind kind = protocol::PacketKind::Unicast;
    std::uint64_t flow_id = 0;
};
class Tunnel {
public:
    Tunnel(NetworkConfig config, unsigned mtu) : config_(config), mtu_(mtu) {}
    // Checks a complete TUN packet. No segmentation or reassembly is performed.
    bool inspect(const std::vector<unsigned char>& packet, PacketInfo* info, bool from_local, bool routed = false) const;
    const NetworkConfig& config() const { return config_; }
    unsigned mtu() const { return mtu_; }
private:
    NetworkConfig config_;
    unsigned mtu_;
};
