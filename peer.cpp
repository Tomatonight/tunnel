#include "peer.h"
#include <utility>
#include <stdexcept>

Peer::Peer(PeerConfig config) : config_(std::move(config)) {}
std::uint64_t Peer::begin_connection() {
    disconnect(); state_ = PEER_STATE_CONNECTING; return generation_;
}
bool Peer::tcp_authenticated(std::uint64_t generation, Time now) {
    if (generation != generation_ || state_ != PEER_STATE_CONNECTING) return false;
    tcp_activity_ = data_ack_ = now; state_ = PEER_STATE_VERIFICATING; return true;
}
void Peer::sent_data_probe(std::uint64_t token) {
    if (state_ != PEER_STATE_VERIFICATING && state_ != PEER_STATE_ESTABLISHED)
        throw std::logic_error("Data probes require an authenticated TCP connection");
    probe_ = token; pending_probe_ = true;
}
bool Peer::authenticated_data_ack(std::uint64_t generation, std::uint64_t token, Time now) {
    if (generation != generation_ || !pending_probe_ || token != probe_ ||
        (state_ != PEER_STATE_VERIFICATING && state_ != PEER_STATE_ESTABLISHED)) return false;
    pending_probe_ = false; data_ack_ = now; state_ = PEER_STATE_ESTABLISHED; return true;
}
void Peer::authenticated_tcp_activity(std::uint64_t generation, Time now) {
    if (generation == generation_ && (state_ == PEER_STATE_VERIFICATING || state_ == PEER_STATE_ESTABLISHED)) tcp_activity_ = now;
}
bool Peer::expired(Time now, std::chrono::milliseconds timeout) const {
    return (state_ == PEER_STATE_VERIFICATING || state_ == PEER_STATE_ESTABLISHED) &&
        (now - tcp_activity_ >= timeout || now - data_ack_ >= timeout);
}
void Peer::disconnect() {
    ++generation_; state_ = PEER_STATE_INIT; pending_probe_ = false; probe_ = 0;
}
bool Peer::allows(const Network& network) const {
    for (const auto& n : config_.networks) if (n.tunnel == network) return true;
    return false;
}
