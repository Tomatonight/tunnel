#pragma once
#include <event2/util.h>
#include <array>
#include <cstdint>
#include <string>

struct IpAddress {
    unsigned family = 4;
    std::array<unsigned char, 16> bytes{};
    static IpAddress parse(const std::string& text);
    std::string str() const;
    bool unspecified() const;
    bool multicast() const;
    bool unicast() const;
    bool operator==(const IpAddress& rhs) const;
    bool operator!=(const IpAddress& rhs) const { return !(*this == rhs); }
    bool operator<(const IpAddress& rhs) const;
};
struct Endpoint {
    IpAddress ip;
    std::uint16_t port = 0;
    static Endpoint parse(const std::string& text);
    static Endpoint from_sockaddr(const sockaddr* address);
    sockaddr_storage sockaddr_value(int* length) const;
    std::string str() const;
    bool operator==(const Endpoint& rhs) const;
    bool operator!=(const Endpoint& rhs) const { return !(*this == rhs); }
    bool operator<(const Endpoint& rhs) const;
};
struct Network {
    IpAddress address;
    unsigned prefix = 0;
    static Network parse(const std::string& text);
    bool contains(const IpAddress& ip) const;
    bool overlaps(const Network& other) const;
    bool usable_host(const IpAddress& ip) const;
    std::string str() const;
    bool operator==(const Network& rhs) const;
    bool operator<(const Network& rhs) const;
};
