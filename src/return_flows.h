#pragma once
#include "address.h"
#include "crypto.h"
#include <chrono>
#include <map>
#include <string>

// Return-path authorization only. Addresses/ports are never translated here;
// system NAT retains ownership of its own mappings and protocol state.
class ReturnFlows {
public:
    using Time = std::chrono::steady_clock::time_point;
    explicit ReturnFlows(std::size_t limit = 1024) : limit_(limit) {}
    bool remember(const Bytes&, const NodeId&, Time now = std::chrono::steady_clock::now());
    bool request_peer(const Bytes&, NodeId*, Time now = std::chrono::steady_clock::now()) const;
    bool reply(const Bytes&, NodeId*, bool* related_error = nullptr, Time now = std::chrono::steady_clock::now(), IpAddress* requested = nullptr);
    void expire(Time now = std::chrono::steady_clock::now());
    void erase_peer(const NodeId&);
    void clear() { flows_.clear(); fragments_.clear(); }
    std::size_t size() const { return flows_.size(); }
private:
    struct Binding { NodeId peer; IpAddress requested; Time expires; unsigned lifetime = 0; };
    struct Fragment { std::string flow; bool reply = false; Time expires; };
    std::map<std::string, Binding> flows_;
    std::map<std::string, Fragment> fragments_;
    std::size_t limit_;
};
