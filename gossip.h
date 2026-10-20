#pragma once
#include "address.h"
#include "crypto.h"
#include "parse_config.h"
#include <map>
#include <set>
#include <vector>

// Each path starts with the publishing peer and ends with the destination.
// Its length is the hop count seen by the receiving node.
struct PathAnnouncement {
    Network network;
    Endpoint destination;
    IpAddress tunnel_ip;
    PublicKey public_key{};
    std::vector<Endpoint> path;
    std::vector<Network> prefixes;
};
class Gossip {
public:
    Gossip(Endpoint local, const std::vector<NetworkConfig>& networks,
           const std::vector<AdvertisedRoute>& advertised = {});
    void authorize(const Endpoint& peer, const std::vector<Network>& networks);
    void forget_peer(const Endpoint& peer); // Remove adjacency routes and cached authorization.
    void set_available(const Endpoint& peer, bool available);
    // Runtime membership changes must not withdraw unrelated networks.
    void set_local_address(const Network&, const IpAddress*);
    // Only configured prefixes whose operating-system setup succeeded are active.
    void set_local_prefixes(const Network&, const std::vector<Network>&);
    // Announce the raw active set even during a conflict, so two publishers do
    // not repeatedly withdraw and reintroduce their conflicting declarations.
    std::vector<Network> active_local_prefixes(const Network&) const;
    void set_authorized_networks(const Endpoint&, const std::vector<Network>&);
    // A freshly verified allocator grant is authoritative for this binding.
    // Clear superseded candidates without touching other virtual networks.
    void confirm_allocated_address(const Network&, const Endpoint&, const IpAddress&);
    bool announce(const Endpoint& peer, const PathAnnouncement& message);
    void withdraw(const Endpoint& peer, const Network& network, const Endpoint& destination);
    std::vector<Endpoint> next_hops(const Network& network, const Endpoint& destination) const;
    bool select_unicast(const Network& network, const Endpoint& destination, std::uint64_t flow, Endpoint* peer) const;
    bool accept_rpf(const Network& network, const Endpoint& source, const Endpoint& incoming) const;
    bool public_key(const Endpoint& destination, PublicKey* key) const;
    bool node_for_ip(const Network& network, const IpAddress& ip, Endpoint* node) const;
    bool ip_for_node(const Network&, const Endpoint&, IpAddress*) const;
    // Includes active local announcements. Conflicting external prefixes are
    // unusable without removing the owning node's ordinary overlay paths.
    std::vector<Network> prefixes_for_node(const Network&, const Endpoint&) const;
    std::vector<Network> advertised_prefixes(const Network&) const;
    bool select_gateway(const Network&, const Network& prefix, Endpoint* gateway) const;
    std::vector<PathAnnouncement> export_to(const Endpoint& peer) const;
    std::vector<PathAnnouncement> snapshot() const;
    std::size_t size() const { return records_.size(); }
private:
    struct Record {
        Endpoint peer;
        PathAnnouncement announcement;
        std::uint64_t order;
    };
    Endpoint local_;
    std::map<Network, IpAddress> local_networks_;
    std::vector<Network> configured_networks_;
    std::vector<AdvertisedRoute> local_prefixes_;
    std::map<Network, std::vector<Network>> active_local_prefixes_;
    std::map<Endpoint, std::set<Network>> allowed_;
    std::set<Endpoint> available_;
    std::vector<Record> records_;
    std::uint64_t next_order_ = 0;
    using Origin = std::pair<Network, Endpoint>;
    mutable bool prefixes_dirty_ = true;
    mutable std::map<Origin, std::vector<Network>> raw_prefixes_;
    mutable std::map<Origin, std::vector<Network>> usable_prefixes_;
    mutable std::map<std::pair<Network, Network>, Endpoint> gateways_;
    void rebuild_prefixes() const;
};
