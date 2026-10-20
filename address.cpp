#include "address.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace {
unsigned decimal(const std::string& text, unsigned maximum) {
    if (text.empty()) throw std::invalid_argument("missing decimal number");
    unsigned result = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9' || unsigned(c - '0') > maximum ||
            result > (maximum - unsigned(c - '0')) / 10)
            throw std::invalid_argument("invalid decimal number: " + text);
        result = result * 10 + unsigned(c - '0');
    }
    return result;
}
IpAddress masked(IpAddress ip, unsigned prefix) {
    for (unsigned i = 0; i < ip.bytes.size(); ++i) {
        const unsigned bits = prefix > i * 8 ? std::min(8u, prefix - i * 8) : 0;
        ip.bytes[i] &= static_cast<unsigned char>(bits ? 0xffu << (8 - bits) : 0);
    }
    return ip;
}
}
IpAddress IpAddress::parse(const std::string& text) {
    IpAddress result;
    if (text.find('\0') != std::string::npos) throw std::invalid_argument("NUL in IP address");
    if (evutil_inet_pton(AF_INET, text.c_str(), result.bytes.data()) == 1) return result;
    result.family = 6;
    if (evutil_inet_pton(AF_INET6, text.c_str(), result.bytes.data()) != 1)
        throw std::invalid_argument("invalid numeric IP address: " + text);
    const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (std::memcmp(result.bytes.data(), mapped, 12) == 0)
        throw std::invalid_argument("use IPv4 notation instead of IPv4-mapped IPv6");
    return result;
}
std::string IpAddress::str() const {
    char text[64]{};
    if (!evutil_inet_ntop(family == 4 ? AF_INET : AF_INET6, bytes.data(), text, sizeof(text)))
        throw std::runtime_error("IP address formatting failed");
    return text;
}
bool IpAddress::unspecified() const {
    return std::all_of(bytes.begin(), bytes.end(), [](unsigned char b) { return b == 0; });
}
bool IpAddress::multicast() const { return family == 4 ? (bytes[0] & 0xf0) == 0xe0 : bytes[0] == 0xff; }
bool IpAddress::unicast() const {
    return !unspecified() && !multicast() && !(family == 4 && (bytes[0] == 0 || bytes[0] >= 240));
}
bool IpAddress::operator==(const IpAddress& rhs) const { return family == rhs.family && bytes == rhs.bytes; }
bool IpAddress::operator<(const IpAddress& rhs) const { return family != rhs.family ? family < rhs.family : bytes < rhs.bytes; }
Endpoint Endpoint::parse(const std::string& text) {
    const bool bracket = !text.empty() && text.front() == '[';
    const auto colon = bracket ? text.find("]:") : text.find(':');
    if (colon == std::string::npos) throw std::invalid_argument("expected IP:port or [IPv6]:port");
    Endpoint result;
    result.ip = IpAddress::parse(text.substr(bracket ? 1 : 0, colon - (bracket ? 1 : 0)));
    if (bracket != (result.ip.family == 6)) throw std::invalid_argument("IPv6 endpoints require brackets");
    result.port = static_cast<std::uint16_t>(decimal(text.substr(colon + (bracket ? 2 : 1)), 65535));
    if (!result.port) throw std::invalid_argument("port must be in 1..65535");
    return result;
}
std::string Endpoint::str() const { return (ip.family == 6 ? "[" + ip.str() + "]" : ip.str()) + ":" + std::to_string(port); }
sockaddr_storage Endpoint::sockaddr_value(int* length) const {
    sockaddr_storage storage{};
    if (ip.family == 4) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_family = AF_INET; v4->sin_port = htons(port);
        std::memcpy(&v4->sin_addr, ip.bytes.data(), 4); *length = sizeof(*v4);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(port);
        std::memcpy(&v6->sin6_addr, ip.bytes.data(), 16); *length = sizeof(*v6);
    }
    return storage;
}
Endpoint Endpoint::from_sockaddr(const sockaddr* address) {
    Endpoint result;
    if (address->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
        result.port = ntohs(v4->sin_port); std::memcpy(result.ip.bytes.data(), &v4->sin_addr, 4);
    } else if (address->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
        result.ip.family = 6; result.port = ntohs(v6->sin6_port); std::memcpy(result.ip.bytes.data(), &v6->sin6_addr, 16);
    } else throw std::invalid_argument("unsupported socket address family");
    return result;
}
bool Endpoint::operator==(const Endpoint& rhs) const { return ip == rhs.ip && port == rhs.port; }
bool Endpoint::operator<(const Endpoint& rhs) const { return ip == rhs.ip ? port < rhs.port : ip < rhs.ip; }
Network Network::parse(const std::string& text) {
    const auto slash = text.find('/');
    if (slash == std::string::npos) throw std::invalid_argument("expected CIDR");
    Network result;
    result.address = IpAddress::parse(text.substr(0, slash));
    result.prefix = decimal(text.substr(slash + 1), result.address.family == 4 ? 32 : 128);
    result.address = masked(result.address, result.prefix); return result;
}
bool Network::contains(const IpAddress& ip) const { return address.family == ip.family && masked(ip, prefix) == address; }
bool Network::overlaps(const Network& other) const { return contains(other.address) || other.contains(address); }
bool Network::usable_host(const IpAddress& ip) const {
    if (!contains(ip) || !ip.unicast()) return false;
    if (address.family == 4 && prefix < 31) {
        if (ip == address) return false;
        IpAddress broadcast = address;
        for (unsigned bit = prefix; bit < 32; ++bit) broadcast.bytes[bit / 8] |= 1u << (7 - bit % 8);
        if (ip == broadcast) return false;
    }
    return true;
}
std::string Network::str() const { return address.str() + "/" + std::to_string(prefix); }
bool Network::operator==(const Network& rhs) const { return address == rhs.address && prefix == rhs.prefix; }
bool Network::operator<(const Network& rhs) const { return address == rhs.address ? prefix < rhs.prefix : address < rhs.address; }
