#pragma once
#include "parse_config.h"
#include <chrono>
#include <cstdint>

enum PeerState {
    PEER_STATE_INIT,
    PEER_STATE_CONNECTING,
    PEER_STATE_VERIFICATING,
    PEER_STATE_ESTABLISHED
};

class Peer {
public:
    using Clock = std::chrono::steady_clock;
    using Time = Clock::time_point;
    explicit Peer(PeerConfig config);
    std::uint64_t begin_connection();
    bool tcp_authenticated(std::uint64_t generation, Time now);
    void sent_data_probe(std::uint64_t token);
    bool authenticated_data_ack(std::uint64_t generation, std::uint64_t token, Time now);
    // Compatibility names for callers testing the original UDP channel.
    void sent_udp_probe(std::uint64_t token) { sent_data_probe(token); }
    bool authenticated_udp_ack(std::uint64_t generation, std::uint64_t token, Time now) {
        return authenticated_data_ack(generation, token, now);
    }
    void authenticated_tcp_activity(std::uint64_t generation, Time now);
    bool expired(Time now, std::chrono::milliseconds timeout) const;
    void disconnect();
    bool allows(const Network& network) const;
    PeerState state() const { return state_; }
    std::uint64_t generation() const { return generation_; }
    const PeerConfig& config() const { return config_; }
private:
    PeerConfig config_;
    PeerState state_ = PEER_STATE_INIT;
    std::uint64_t generation_ = 0, probe_ = 0;
    bool pending_probe_ = false;
    Time tcp_activity_{}, data_ack_{};
};
