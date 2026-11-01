#include "wire.h"
#include <algorithm>
namespace wire {
std::string hex(const unsigned char* data, std::size_t size) {
    const char* digits = "0123456789abcdef"; std::string result; result.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) { result += digits[data[i] >> 4]; result += digits[data[i] & 15]; }
    return result;
}
Bytes unhex(const std::string& value, std::size_t maximum) {
    if (value.size() % 2 || value.size() / 2 > maximum) throw std::invalid_argument("invalid hex length");
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::invalid_argument("invalid hex digit");
    };
    Bytes out; out.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) out.push_back(static_cast<unsigned char>((digit(value[i]) << 4) | digit(value[i+1])));
    return out;
}
PublicKey key(const Json& value) {
    auto bytes = unhex(value.get<std::string>(), 32); PublicKey result{};
    if (bytes.size() != result.size() || std::all_of(bytes.begin(), bytes.end(), [](unsigned char c) { return c == 0; }))
        throw std::invalid_argument("invalid identity key");
    std::copy(bytes.begin(), bytes.end(), result.begin()); return result;
}
Json route(const PathAnnouncement& a) {
    Json paths = Json::array(); for (const auto& p : a.path) paths.push_back(p.str());
    Json result = {{"type", "route"}, {"network", a.network.str()}, {"node", a.destination.str()},
                   {"ip", a.tunnel_ip.str()}, {"key", hex(a.public_key)}, {"path", paths}};
    if (!a.prefixes.empty()) {
        result["prefixes"] = Json::array();
        for (const auto& prefix : a.prefixes) result["prefixes"].push_back(prefix.str());
    }
    return result;
}
PathAnnouncement route(const Json& j) {
    PathAnnouncement a; a.network = Network::parse(j.at("network").get<std::string>());
    a.destination = Endpoint::parse(j.at("node").get<std::string>());
    a.tunnel_ip = IpAddress::parse(j.at("ip").get<std::string>()); a.public_key = key(j.at("key"));
    const auto& path = j.at("path");
    if (!path.is_array() || path.empty() || path.size() > 64) throw std::invalid_argument("path length");
    for (const auto& p : path) a.path.push_back(Endpoint::parse(p.get<std::string>()));
    if (j.count("prefixes")) {
        const auto& prefixes = j.at("prefixes");
        if (!prefixes.is_array() || prefixes.size() > 64) throw std::invalid_argument("advertised prefix limit");
        for (const auto& p : prefixes) {
            const auto text = p.get<std::string>(); const auto prefix = Network::parse(text);
            if (!(IpAddress::parse(text.substr(0, text.find('/'))) == prefix.address) ||
                !valid_advertised_prefix(prefix) || prefix.address.family != a.network.address.family || prefix.overlaps(a.network))
                throw std::invalid_argument("invalid advertised prefix");
            for (const auto& old : a.prefixes) if (old.overlaps(prefix))
                throw std::invalid_argument("duplicate or overlapping advertised prefixes");
            a.prefixes.push_back(prefix);
        }
        std::sort(a.prefixes.begin(), a.prefixes.end());
    }
    return a;
}
Bytes frame(const Json& message) {
    const auto text = message.dump();
    if (text.empty() || text.size() > max_frame) throw std::length_error("control frame limit");
    Bytes out;
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<unsigned char>(text.size() >> shift));
    out.insert(out.end(), text.begin(), text.end()); return out;
}
void Decoder::append(const Bytes& bytes) {
    if (bytes_.size() - offset_ + bytes.size() > max_frame * 8) throw std::length_error("framed receive limit");
    if (offset_) {
        bytes_.erase(bytes_.begin(), bytes_.begin() + offset_); offset_ = 0;
    }
    bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
}
Bytes data_frame(const Bytes& packet) {
    if (packet.empty() || packet.size() > max_data_frame) throw std::length_error("data frame limit");
    const std::uint32_t length = 0x80000000u | static_cast<std::uint32_t>(packet.size());
    Bytes result; result.reserve(packet.size() + 4);
    for (int shift = 24; shift >= 0; shift -= 8) result.push_back(static_cast<unsigned char>(length >> shift));
    result.insert(result.end(), packet.begin(), packet.end()); return result;
}
bool Decoder::next(Json& message) { return next_frame(message, nullptr); }
bool Decoder::next(Json& message, Bytes& packet) { return next_frame(message, &packet); }
bool Decoder::next_frame(Json& message, Bytes* packet) {
    if (bytes_.size() - offset_ < 4) return false;
    std::uint32_t length = 0;
    for (unsigned i = 0; i < 4; ++i) length = (length << 8) | bytes_[offset_ + i];
    const bool binary = (length & 0x80000000u) != 0;
    const std::size_t size = length & 0x7fffffffu;
    if (!size || size > (binary ? max_data_frame : max_frame)) throw std::length_error("frame length");
    if (binary && !packet) throw std::invalid_argument("binary data not allowed on this connection");
    if (bytes_.size() - offset_ < size + 4) return false;
    const auto begin = bytes_.begin() + offset_ + 4;
    if (binary) {
        packet->assign(begin, begin + size); message = Json();
    } else {
    if (packet) packet->clear();
    message = Json::parse(begin, begin + size,
        [](int depth, Json::parse_event_t, Json&) { if (depth > 16) throw std::length_error("JSON depth"); return true; });
    if (!message.is_object()) throw std::invalid_argument("control message must be object");
    }
    offset_ += size + 4;
    if (offset_ == bytes_.size()) { bytes_.clear(); offset_ = 0; }
    return true;
}
}
