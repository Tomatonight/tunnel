#include "return_flows.h"
#include <algorithm>

namespace {
unsigned be16(const unsigned char* p) { return (unsigned(p[0]) << 8) | p[1]; }
struct Packet {
    IpAddress source, destination;
    unsigned protocol = 0, offset = 0;
    bool fragmented = false, later = false;
    std::string fragment;
};
std::string addresses(const IpAddress& source, const IpAddress& destination, unsigned protocol) {
    std::string key(1, static_cast<char>(source.family));
    key.append(reinterpret_cast<const char*>(source.bytes.data()), 16);
    key.append(reinterpret_cast<const char*>(destination.bytes.data()), 16);
    key.push_back(static_cast<char>(protocol)); return key;
}
bool parse(const Bytes& bytes, Packet& p, bool quoted = false) {
    if (bytes.size() < 20) return false;
    const auto version = bytes[0] >> 4;
    std::string id;
    unsigned fragment_protocol = 0;
    if (version == 4) {
        p.offset = (bytes[0] & 15) * 4;
        const auto length = be16(&bytes[2]);
        if (p.offset < 20 || p.offset > bytes.size() || length < p.offset || (!quoted && length != bytes.size())) return false;
        std::copy_n(bytes.begin() + 12, 4, p.source.bytes.begin());
        std::copy_n(bytes.begin() + 16, 4, p.destination.bytes.begin()); p.protocol = bytes[9];
        const auto fragment = be16(&bytes[6]);
        p.fragmented = (fragment & 0x3fff) != 0; p.later = (fragment & 0x1fff) != 0;
        fragment_protocol = p.protocol;
        if (p.fragmented) id.assign(reinterpret_cast<const char*>(&bytes[4]), 2);
    } else if (version == 6) {
        if (bytes.size() < 40 || (!quoted && 40u + be16(&bytes[4]) != bytes.size())) return false;
        p.source.family = p.destination.family = 6;
        std::copy_n(bytes.begin() + 8, 16, p.source.bytes.begin());
        std::copy_n(bytes.begin() + 24, 16, p.destination.bytes.begin()); p.protocol = bytes[6]; p.offset = 40;
        bool fragment_seen = false;
        for (unsigned count = 0; count < 16; ++count) {
            if (p.protocol == 44) {
                if (fragment_seen || p.offset + 8 > bytes.size()) return false;
                fragment_seen = true;
                const auto fragment = be16(&bytes[p.offset + 2]);
                // An atomic fragment is a complete packet, not permission for
                // later fragments which happen to reuse its identification.
                p.fragmented = (fragment & 0xfff9) != 0; p.later = (fragment & 0xfff8) != 0;
                id.assign(reinterpret_cast<const char*>(&bytes[p.offset + 4]), 4);
                fragment_protocol = bytes[p.offset];
                p.protocol = fragment_protocol; p.offset += 8;
                if (p.later) break;
                // The first fragment can contain destination options or AH
                // before its transport header. Later fragments have no such
                // guarantee and must use the first fragment's authorization.
                continue;
            }
            if (p.protocol != 0 && p.protocol != 43 && p.protocol != 60 && p.protocol != 51) break;
            if (p.offset + 2 > bytes.size()) return false;
            const auto length = p.protocol == 51 ? (bytes[p.offset + 1] + 2u) * 4 : (bytes[p.offset + 1] + 1u) * 8;
            if (p.offset + length > bytes.size() || count == 15) return false;
            p.protocol = bytes[p.offset]; p.offset += length;
        }
    } else return false;
    if (!p.source.unicast() || !p.destination.unicast()) return false;
    if (p.fragmented) p.fragment = addresses(p.source, p.destination, fragment_protocol) + id;
    return true;
}
bool tuple(const Bytes& bytes, const Packet& p, bool reply, std::string& key, unsigned& lifetime) {
    if (p.later || p.offset + 4 > bytes.size()) return false;
    key = reply ? addresses(p.destination, p.source, p.protocol) : addresses(p.source, p.destination, p.protocol);
    if (p.protocol == 6 || p.protocol == 17) {
        if (reply && p.protocol == 6) {
            if (p.offset + 14 > bytes.size()) return false;
            const auto flags = bytes[p.offset + 13];
            if ((flags & 2) && !(flags & 16)) return false;
        }
        const auto* ports = &bytes[p.offset];
        key.append(reinterpret_cast<const char*>(ports + (reply ? 2 : 0)), 2);
        key.append(reinterpret_cast<const char*>(ports + (reply ? 0 : 2)), 2);
        lifetime = p.protocol == 6 ? 7200 : 120; return true;
    }
    if (p.protocol != 1 && p.protocol != 58) return false;
    const unsigned type = p.protocol == 1 ? (reply ? 0 : 8) : (reply ? 129 : 128);
    if (p.offset + 8 > bytes.size() || bytes[p.offset] != type || bytes[p.offset + 1] != 0) return false;
    key.append(reinterpret_cast<const char*>(&bytes[p.offset + 4]), 2);
    lifetime = 30; return true;
}
bool error_tuple(const Bytes& bytes, const Packet& p, std::string& key) {
    if (p.later || p.offset + 8 > bytes.size()) return false;
    const auto type = bytes[p.offset];
    if (!((p.protocol == 1 && (type == 3 || type == 11 || type == 12)) || (p.protocol == 58 && type >= 1 && type <= 4))) return false;
    Bytes quotation(bytes.begin() + p.offset + 8, bytes.end()); Packet inner; unsigned lifetime;
    return parse(quotation, inner, true) && p.destination == inner.source && tuple(quotation, inner, false, key, lifetime);
}
}
bool ReturnFlows::remember(const Bytes& bytes, const Endpoint& peer, Time now) {
    Packet packet; if (!peer.port || !parse(bytes, packet)) return false;
    if (packet.later) { Endpoint found; return request_peer(bytes, &found, now) && found == peer; }
    std::string key; unsigned lifetime;
    if (!tuple(bytes, packet, false, key, lifetime)) return false;
    auto found = flows_.find(key);
    if (found == flows_.end() && flows_.size() >= limit_) { expire(now); if (flows_.size() >= limit_) return false; }
    Binding binding; binding.peer = peer; binding.requested = packet.destination; binding.lifetime = lifetime; binding.expires = now + std::chrono::seconds(lifetime);
    flows_[key] = binding;
    if (packet.fragmented && fragments_.size() < limit_) {
        Fragment fragment; fragment.flow = key; fragment.expires = now + std::chrono::seconds(30);
        fragments_[packet.fragment] = fragment;
    }
    return true;
}
bool ReturnFlows::request_peer(const Bytes& bytes, Endpoint* peer, Time now) const {
    Packet packet; if (!peer || !parse(bytes, packet)) return false;
    std::string key; unsigned lifetime;
    if (packet.later) {
        const auto fragment = fragments_.find(packet.fragment);
        if (fragment == fragments_.end() || fragment->second.reply || fragment->second.expires <= now) return false;
        key = fragment->second.flow;
    } else if (!tuple(bytes, packet, false, key, lifetime)) return false;
    const auto found = flows_.find(key);
    if (found == flows_.end() || found->second.expires <= now) return false;
    *peer = found->second.peer; return true;
}
bool ReturnFlows::reply(const Bytes& bytes, Endpoint* peer, bool* related, Time now, IpAddress* requested) {
    Packet packet; if (!peer || !parse(bytes, packet)) return false;
    if (related) *related = false;
    std::string key; unsigned lifetime; bool error = false;
    if (packet.later) {
        const auto fragment = fragments_.find(packet.fragment);
        if (fragment == fragments_.end() || !fragment->second.reply || fragment->second.expires <= now) return false;
        key = fragment->second.flow;
    } else if (!tuple(bytes, packet, true, key, lifetime)) {
        if (!error_tuple(bytes, packet, key)) return false;
        error = true;
    }
    auto found = flows_.find(key);
    if (found == flows_.end() || found->second.expires <= now) return false;
    // Errors do not keep a dead request alive indefinitely.
    if (!error) found->second.expires = now + std::chrono::seconds(found->second.lifetime);
    *peer = found->second.peer; if (related) *related = error; if (requested) *requested = found->second.requested;
    if (packet.fragmented && !packet.later && !error && fragments_.size() < limit_) {
        Fragment fragment; fragment.flow = key; fragment.reply = true; fragment.expires = now + std::chrono::seconds(30);
        fragments_[packet.fragment] = fragment;
    }
    return true;
}
void ReturnFlows::expire(Time now) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (it->second.expires <= now) it = flows_.erase(it); else ++it;
    }
    for (auto it = fragments_.begin(); it != fragments_.end();) {
        if (it->second.expires <= now || !flows_.count(it->second.flow)) it = fragments_.erase(it); else ++it;
    }
}
void ReturnFlows::erase_peer(const Endpoint& peer) {
    for (auto it = flows_.begin(); it != flows_.end();) { if (it->second.peer == peer) it = flows_.erase(it); else ++it; }
    expire();
}
