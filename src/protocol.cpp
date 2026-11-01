#include "protocol.h"
#include <algorithm>
#include <stdexcept>

namespace protocol {
namespace {
void put16(std::vector<unsigned char>& out, unsigned value) {
    out.push_back(static_cast<unsigned char>(value >> 8)); out.push_back(static_cast<unsigned char>(value));
}
void put_ip(std::vector<unsigned char>& out, const IpAddress& ip) {
    out.push_back(static_cast<unsigned char>(ip.family)); out.insert(out.end(), ip.bytes.begin(), ip.bytes.end());
}
// Keep the historical 70-byte header layout: each virtual node slot is an IP
// address followed by a reserved u16.  The reserved field must be zero so a
// future format can be detected instead of silently misinterpreted.
void put_node(std::vector<unsigned char>& out, const IpAddress& node) { put_ip(out, node); put16(out, 0); }
bool get_ip(const std::vector<unsigned char>& in, std::size_t& pos, IpAddress& ip) {
    ip.family = in[pos++];
    if (ip.family != 4 && ip.family != 6) return false;
    std::copy_n(in.begin() + pos, 16, ip.bytes.begin()); pos += 16;
    if (ip.family == 4 && !std::all_of(ip.bytes.begin() + 4, ip.bytes.end(), [](unsigned char c) { return c == 0; })) return false;
    try { return IpAddress::parse(ip.str()) == ip; } catch (const std::invalid_argument&) { return false; }
}
unsigned get16(const std::vector<unsigned char>& in, std::size_t& pos) {
    const unsigned n = (unsigned(in[pos]) << 8) | in[pos + 1]; pos += 2; return n;
}
bool get_node(const std::vector<unsigned char>& in, std::size_t& pos, IpAddress& node) {
    if (!get_ip(in, pos, node)) return false;
    return get16(in, pos) == 0;
}
}
std::size_t outer_overhead(unsigned family) {
    if (family != 4 && family != 6) throw std::invalid_argument("invalid outer IP family");
    return (family == 4 ? 20 : 40) + 8;
}
std::size_t maximum_tun_mtu(std::size_t transport_mtu, unsigned family) {
    const auto overhead = outer_overhead(family) + unicast_overhead;
    return transport_mtu > overhead ? transport_mtu - overhead : 0;
}
std::vector<unsigned char> encode(const ForwardHeader& h, const std::vector<unsigned char>& payload) {
    if (payload.size() > 65535) throw std::length_error("forwarded payload exceeds wire length");
    std::vector<unsigned char> out{forwarding_version, static_cast<unsigned char>(h.kind), h.hop_limit, 0};
    put_ip(out, h.network.address); out.push_back(static_cast<unsigned char>(h.network.prefix));
    put_node(out, h.source); put_node(out, h.destination);
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<unsigned char>(h.flow_id >> shift));
    put16(out, static_cast<unsigned>(payload.size())); out.insert(out.end(), payload.begin(), payload.end()); return out;
}
bool decode(const std::vector<unsigned char>& in, ForwardHeader* header, std::vector<unsigned char>* payload) {
    if (!header || !payload || in.size() < forwarding_header_size || in[0] != forwarding_version || in[3] != 0 || in[1] < 1 || in[1] > 3 || in[2] == 0) return false;
    ForwardHeader h; h.kind = static_cast<PacketKind>(in[1]); h.hop_limit = in[2];
    std::size_t pos = 4;
    if (!get_ip(in, pos, h.network.address)) return false;
    h.network.prefix = in[pos++];
    try { if (!(Network::parse(h.network.str()) == h.network)) return false; }
    catch (const std::invalid_argument&) { return false; }
    if (!get_node(in, pos, h.source) || !get_node(in, pos, h.destination)) return false;
    if (!h.source.unicast()) return false;
    if (h.kind == PacketKind::Unicast) { if (!h.destination.unicast()) return false; }
    else if (!h.destination.unspecified()) return false;
    for (unsigned i = 0; i < 8; ++i) h.flow_id = (h.flow_id << 8) | in[pos++];
    const unsigned length = get16(in, pos);
    if (in.size() != forwarding_header_size + length) return false;
    *header = h; payload->assign(in.begin() + pos, in.end()); return true;
}
std::vector<unsigned char> end_to_end_aad(const ForwardHeader& h) {
    auto bytes = encode(h, {}); bytes[2] = 0;
    bytes.resize(forwarding_header_size - 2); return bytes;
}
}
