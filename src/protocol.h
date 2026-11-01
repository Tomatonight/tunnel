#pragma once
#include "address.h"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace protocol {
// A node identity is its virtual address on the advertised tunnel network.
// Physical endpoints are transport addresses and are deliberately not carried
// in the inner forwarding header.
using NodeId = IpAddress;
// Big-endian fields. Address slots are fixed width for either inner IP family.
constexpr std::size_t record_header_size = 32; // magic(4), version, kind, len(2), session(16), seq(8)
constexpr std::size_t authentication_tag_size = 16;
constexpr std::size_t record_overhead = record_header_size + authentication_tag_size;
constexpr std::size_t forwarding_header_size = 70;
constexpr unsigned char forwarding_version = 2;
constexpr std::size_t unicast_overhead = forwarding_header_size + 2 * record_overhead;
constexpr unsigned default_hop_limit = 32;
std::size_t outer_overhead(unsigned family);
std::size_t maximum_tun_mtu(std::size_t transport_mtu, unsigned outer_family);
enum class PacketKind : unsigned char { Unicast = 1, Broadcast = 2, Multicast = 3 };
struct ForwardHeader {
    PacketKind kind = PacketKind::Unicast;
    unsigned char hop_limit = default_hop_limit;
    Network network;
    NodeId source;
    NodeId destination; // unspecified address for broadcast/multicast
    std::uint64_t flow_id = 0;
};
std::vector<unsigned char> encode(const ForwardHeader& header, const std::vector<unsigned char>& payload);
bool decode(const std::vector<unsigned char>& packet, ForwardHeader* header, std::vector<unsigned char>* payload);
std::vector<unsigned char> end_to_end_aad(const ForwardHeader& header);
}
