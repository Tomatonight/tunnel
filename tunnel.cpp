#include "tunnel.h"
#include <algorithm>

namespace {
unsigned be16(const unsigned char* p) { return (unsigned(p[0]) << 8) | p[1]; }
void hash_byte(std::uint64_t& hash, unsigned char byte) { hash = (hash ^ byte) * 1099511628211ULL; }
}
bool Tunnel::inspect(const std::vector<unsigned char>& packet, PacketInfo* info, bool from_local, bool routed) const {
    if (!info || packet.empty() || packet.size() > mtu_) return false;
    PacketInfo result;
    unsigned protocol_number = 0;
    std::size_t transport_offset = 0;
    bool fragmented = false;
    const unsigned version = packet[0] >> 4;
    if (version == 4) {
        if (packet.size() < 20) return false;
        const unsigned header = (packet[0] & 15) * 4;
        if (header < 20 || header > packet.size() || be16(&packet[2]) != packet.size()) return false;
        std::copy_n(packet.begin() + 12, 4, result.source.bytes.begin());
        std::copy_n(packet.begin() + 16, 4, result.destination.bytes.begin());
        protocol_number = packet[9]; transport_offset = header;
        fragmented = (be16(&packet[6]) & 0x3fff) != 0;
    } else if (version == 6) {
        if (packet.size() < 40 || 40u + be16(&packet[4]) != packet.size()) return false;
        result.source.family = result.destination.family = 6;
        std::copy_n(packet.begin() + 8, 16, result.source.bytes.begin());
        std::copy_n(packet.begin() + 24, 16, result.destination.bytes.begin());
        protocol_number = packet[6]; transport_offset = 40;
        // Walk only bounded, standard extension headers. Fragmented traffic uses
        // address/protocol affinity so first and later fragments agree.
        for (unsigned count = 0; count < 16; ++count) {
            if (protocol_number == 44) {
                if (transport_offset + 8 > packet.size()) return false;
                protocol_number = packet[transport_offset]; fragmented = true; break;
            }
            if (protocol_number != 0 && protocol_number != 43 && protocol_number != 60 && protocol_number != 51) break;
            if (transport_offset + 2 > packet.size()) return false;
            const auto size = protocol_number == 51 ? (packet[transport_offset + 1] + 2u) * 4u : (packet[transport_offset + 1] + 1u) * 8u;
            if (transport_offset + size > packet.size()) return false;
            protocol_number = packet[transport_offset]; transport_offset += size;
            if (count == 15) return false;
        }
    } else return false;
    if (routed) {
        if (!result.source.unicast() || result.source.family != config_.tunnel.address.family) return false;
    } else if (!config_.tunnel.usable_host(result.source) || (from_local && result.source != config_.tunnel_ip)) return false;
    if (result.destination.multicast()) result.kind = protocol::PacketKind::Multicast;
    else if (version == 4) {
        IpAddress broadcast = config_.tunnel.address;
        for (unsigned bit = config_.tunnel.prefix; bit < 32; ++bit) broadcast.bytes[bit / 8] |= 1u << (7 - bit % 8);
        const bool limited = result.destination.bytes[0] == 255 && result.destination.bytes[1] == 255 &&
            result.destination.bytes[2] == 255 && result.destination.bytes[3] == 255;
        if (limited || (config_.tunnel.prefix < 31 && result.destination == broadcast)) result.kind = protocol::PacketKind::Broadcast;
    }
    if (result.kind == protocol::PacketKind::Unicast && !(routed ? result.destination.unicast() : config_.tunnel.usable_host(result.destination))) return false;
    result.flow_id = 14695981039346656037ULL;
    hash_byte(result.flow_id, static_cast<unsigned char>(version));
    for (auto b : result.source.bytes) hash_byte(result.flow_id, b);
    for (auto b : result.destination.bytes) hash_byte(result.flow_id, b);
    hash_byte(result.flow_id, static_cast<unsigned char>(protocol_number));
    if (!fragmented && (protocol_number == 6 || protocol_number == 17)) {
        if (transport_offset + 4 > packet.size()) return false;
        for (unsigned i = 0; i < 4; ++i) hash_byte(result.flow_id, packet[transport_offset + i]);
    }
    *info = result; return true;
}
