#include "gossip.h"
#include <algorithm>
#include <limits>
#include <stdexcept>

Gossip::Gossip(const std::vector<NetworkConfig>& networks,
               const std::vector<AdvertisedRoute>& advertised) : local_prefixes_(advertised) {
    for (const auto& n : networks) {
        for (const auto& old : configured_networks_)
            if (old.overlaps(n.tunnel)) throw std::invalid_argument("duplicate or overlapping local networks");
        configured_networks_.push_back(n.tunnel);
        if (n.allocation_server.port && n.tunnel_ip.unspecified()) continue;
        if (!n.tunnel.usable_host(n.tunnel_ip)) throw std::invalid_argument("invalid local network address");
        local_networks_[n.tunnel] = n.tunnel_ip;
    }
    if (advertised.size() > 64) throw std::invalid_argument("advertised prefix limit");
    std::vector<Network> seen;
    for (const auto& r : advertised) {
        if (std::find(configured_networks_.begin(), configured_networks_.end(), r.tunnel) == configured_networks_.end() ||
            r.tunnel.address.family != r.prefix.address.family || !valid_advertised_prefix(r.prefix))
            throw std::invalid_argument("invalid configured advertised prefix");
        for (const auto& n : configured_networks_) if (r.prefix.overlaps(n))
            throw std::invalid_argument("advertised prefix overlaps a local tunnel");
        for (const auto& n : seen) if (r.prefix.overlaps(n))
            throw std::invalid_argument("duplicate or overlapping configured advertised prefixes");
        seen.push_back(r.prefix);
    }
}
void Gossip::set_local_address(const Network& network, const IpAddress* address) {
    if (address && !network.usable_host(*address)) throw std::invalid_argument("invalid local network address");
    const auto old = local_networks_.find(network);
    if (address && old != local_networks_.end() && old->second == *address) return;
    records_.erase(std::remove_if(records_.begin(), records_.end(),
        [&](const Record& r) { return r.announcement.network == network; }), records_.end());
    if (address) local_networks_[network] = *address;
    else { local_networks_.erase(network); active_local_prefixes_.erase(network); }
    prefixes_dirty_ = true;
}
void Gossip::set_local_prefixes(const Network& network, const std::vector<Network>& prefixes) {
    if (!prefixes.empty() && !local_networks_.count(network)) throw std::invalid_argument("inactive local tunnel");
    std::set<Network> selected;
    for (const auto& prefix : prefixes) {
        const auto configured = std::find_if(local_prefixes_.begin(), local_prefixes_.end(), [&](const AdvertisedRoute& r) {
            return r.tunnel == network && r.prefix == prefix;
        });
        if (configured == local_prefixes_.end() || !selected.insert(prefix).second)
            throw std::invalid_argument("unconfigured or duplicate active prefix");
    }
    const std::vector<Network> sorted(selected.begin(), selected.end());
    if (active_local_prefixes_[network] != sorted) {
        active_local_prefixes_[network] = sorted; prefixes_dirty_ = true;
    }
}
std::vector<Network> Gossip::active_local_prefixes(const Network& network) const {
    const auto found = active_local_prefixes_.find(network);
    return local_networks_.count(network) && found != active_local_prefixes_.end() ? found->second : std::vector<Network>();
}
void Gossip::set_authorized_networks(const Endpoint& peer, const std::vector<Network>& networks) {
    for (const auto& n : networks) if (!local_networks_.count(n)) throw std::invalid_argument("node has not joined this network");
    const std::set<Network> selected(networks.begin(), networks.end());
    records_.erase(std::remove_if(records_.begin(), records_.end(),
        [&](const Record& r) { return r.peer == peer && !selected.count(r.announcement.network); }), records_.end());
    allowed_[peer] = selected;
    prefixes_dirty_ = true;
}
void Gossip::set_peer_nodes(const Endpoint& peer, const std::map<Network, NodeId>& nodes) {
    for (const auto& item : nodes) {
        if (!local_networks_.count(item.first) || !item.second.unicast() || !item.first.usable_host(item.second))
            throw std::invalid_argument("invalid peer network identity");
    }
    peer_nodes_[peer] = nodes;
}
void Gossip::confirm_allocated_address(const Network& network, const NodeId& node, const IpAddress& address) {
    records_.erase(std::remove_if(records_.begin(), records_.end(), [&](const Record& record) {
        const auto& a = record.announcement;
        return a.network == network && ((a.destination == node && a.tunnel_ip != address) ||
            (a.destination != node && a.tunnel_ip == address));
    }), records_.end());
    prefixes_dirty_ = true;
}
void Gossip::authorize(const Endpoint& peer, const std::vector<Network>& networks) {
    for (const auto& n : networks) if (!local_networks_.count(n)) throw std::invalid_argument("node has not joined this network");
    set_available(peer, false);
    allowed_[peer] = std::set<Network>(networks.begin(), networks.end());
}
void Gossip::set_available(const Endpoint& peer, bool available) {
    if (available) {
        if (!allowed_.count(peer)) throw std::invalid_argument("unknown peer");
        available_.insert(peer);
    } else {
        available_.erase(peer);
        // Only remove records LEARNED FROM this adjacency.
        records_.erase(std::remove_if(records_.begin(), records_.end(),
            [&](const Record& record) { return record.peer == peer; }), records_.end());
        prefixes_dirty_ = true;
    }
}
void Gossip::forget_peer(const Endpoint& peer) {
    set_available(peer, false);
    allowed_.erase(peer);
    peer_nodes_.erase(peer);
}
bool Gossip::announce(const Endpoint& peer, const PathAnnouncement& message) {
    if (records_.size() >= 8192) {
        bool existing = false;
        for (const auto& r : records_) if (r.peer == peer && r.announcement.network == message.network &&
            r.announcement.destination == message.destination) existing = true;
        if (!existing) return false;
    }
    auto allowed = allowed_.find(peer);
    const auto local = local_networks_.find(message.network);
    const auto identity = peer_nodes_.find(peer);
    if (!available_.count(peer) || allowed == allowed_.end() || !allowed->second.count(message.network) ||
        local == local_networks_.end() || !message.network.usable_host(message.tunnel_ip) || message.destination == local->second ||
        message.path.empty() || message.path.size() > 64 ||
        message.path.back() != message.destination) return false;
    if (identity == peer_nodes_.end()) return false;
    const auto identity_for_network = identity->second.find(message.network);
    if (identity_for_network == identity->second.end() ||
        message.path.front() != identity_for_network->second || message.tunnel_ip == local->second || message.prefixes.size() > 64 ||
        std::all_of(message.public_key.begin(), message.public_key.end(), [](unsigned char b) { return b == 0; })) return false;
    std::set<Network> prefixes;
    for (const auto& prefix : message.prefixes) {
        if (!valid_advertised_prefix(prefix) || prefix.address.family != message.network.address.family ||
            prefix.overlaps(message.network) || !prefixes.insert(prefix).second) return false;
        for (const auto& old : prefixes) if (!(old == prefix) && old.overlaps(prefix)) return false;
    }
    std::set<NodeId> visited;
    for (const auto& node : message.path)
        if (!node.unicast() || !visited.insert(node).second) return false;
    for (const auto& record : records_) {
        const auto& old = record.announcement;
        if (!(old.network == message.network)) continue;
        if (old.destination != message.destination && old.tunnel_ip == message.tunnel_ip) return false;
        if (old.destination == message.destination && old.tunnel_ip != message.tunnel_ip &&
            record.peer != peer) return false;
    }
    withdraw(peer, message.network, message.destination);
    Record record; record.peer = peer; record.announcement = message; record.order = ++next_order_;
    records_.push_back(std::move(record)); return true;
}
void Gossip::withdraw(const Endpoint& peer, const Network& network, const NodeId& destination) {
    records_.erase(std::remove_if(records_.begin(), records_.end(), [&](const Record& r) {
        return r.peer == peer && r.announcement.network == network && r.announcement.destination == destination;
    }), records_.end());
    prefixes_dirty_ = true;
}
std::vector<Endpoint> Gossip::next_hops(const Network& network, const NodeId& destination) const {
    std::size_t best = std::numeric_limits<std::size_t>::max();
    std::set<Endpoint> selected;
    for (const auto& record : records_) {
        const auto& a = record.announcement;
        if (!(a.network == network) || a.destination != destination) continue;
        if (a.path.size() < best) { selected.clear(); best = a.path.size(); }
        if (a.path.size() == best) selected.insert(record.peer);
    }
    return std::vector<Endpoint>(selected.begin(), selected.end());
}
bool Gossip::select_unicast(const Network& network, const NodeId& destination, std::uint64_t flow, Endpoint* peer) const {
    const auto candidates = next_hops(network, destination);
    if (!peer || candidates.empty()) return false;
    // Stable mixing; unlike std::hash, explicitly reproducible across platforms.
    flow ^= flow >> 30; flow *= 0xbf58476d1ce4e5b9ULL;
    flow ^= flow >> 27; flow *= 0x94d049bb133111ebULL; flow ^= flow >> 31;
    *peer = candidates[flow % candidates.size()]; return true;
}
bool Gossip::accept_rpf(const Network& network, const NodeId& source, const Endpoint& incoming) const {
    const auto local = local_networks_.find(network);
    if (local != local_networks_.end() && source == local->second) return false;
    const auto candidates = next_hops(network, source);
    return !candidates.empty() && incoming == candidates.front();
}
bool Gossip::public_key(const Network& network, const NodeId& destination, PublicKey* key) const {
    const Record* latest = nullptr;
    for (const auto& r : records_)
        if (r.announcement.network == network && r.announcement.destination == destination && (!latest || r.order > latest->order)) latest = &r;
    if (!latest || !key) return false;
    *key = latest->announcement.public_key; return true;
}
bool Gossip::node_for_ip(const Network& network, const IpAddress& ip, NodeId* node) const {
    if (!node) return false;
    for (const auto& r : records_) if (r.announcement.network == network && r.announcement.tunnel_ip == ip) {
        *node = r.announcement.destination; return true;
    }
    return false;
}
bool Gossip::ip_for_node(const Network& network, const NodeId& node, IpAddress* ip) const {
    if (!ip) return false;
    for (const auto& r : records_) if (r.announcement.network == network && r.announcement.destination == node) {
        *ip = r.announcement.tunnel_ip; return true;
    }
    return false;
}
void Gossip::rebuild_prefixes() const {
    if (!prefixes_dirty_) return;
    raw_prefixes_.clear(); usable_prefixes_.clear(); gateways_.clear();
    std::map<Origin, const Record*> latest;
    std::map<Origin, std::size_t> distances;
    for (const auto& r : records_) {
        const Origin origin(r.announcement.network, r.announcement.destination);
        const auto old = latest.find(origin);
        if (old == latest.end() || old->second->order < r.order) latest[origin] = &r;
        const auto distance = distances.find(origin);
        if (distance == distances.end() || r.announcement.path.size() < distance->second)
            distances[origin] = r.announcement.path.size();
    }
    for (const auto& item : latest) raw_prefixes_[item.first] = item.second->announcement.prefixes;
    for (const auto& item : active_local_prefixes_) if (local_networks_.count(item.first)) {
        const auto local = local_networks_.find(item.first);
        if (local != local_networks_.end()) {
            const Origin origin(item.first, local->second); raw_prefixes_[origin] = item.second; distances[origin] = 0;
        }
    }
    // Sort by subnet base, then prefix length: ancestors precede descendants.
    // At most 128 ancestors can overlap one canonical CIDR, avoiding a quadratic
    // comparison of every announced prefix on each data packet.
    std::map<Network, std::set<Network>> groups;
    for (const auto& r : local_prefixes_) groups[r.prefix].insert(r.tunnel);
    for (const auto& item : raw_prefixes_) for (const auto& prefix : item.second)
        groups[prefix].insert(item.first.first);
    std::set<Network> blocked;
    std::vector<Network> ancestors;
    for (const auto& item : groups) {
        const auto& prefix = item.first;
        if (item.second.size() > 1) blocked.insert(prefix);
        for (const auto& tunnel : configured_networks_) if (prefix.overlaps(tunnel)) blocked.insert(prefix);
        while (!ancestors.empty() && !ancestors.back().contains(prefix.address)) ancestors.pop_back();
        for (const auto& ancestor : ancestors) { blocked.insert(ancestor); blocked.insert(prefix); }
        ancestors.push_back(prefix);
    }
    std::map<std::pair<Network, Network>, std::size_t> best;
    for (const auto& item : raw_prefixes_) {
        std::set<Network> unique;
        for (const auto& prefix : item.second) if (!blocked.count(prefix)) unique.insert(prefix);
        usable_prefixes_[item.first] = std::vector<Network>(unique.begin(), unique.end());
        for (const auto& prefix : unique) {
            const auto key = std::make_pair(item.first.first, prefix);
            const auto distance = distances.at(item.first);
            const auto old = best.find(key);
            if (old == best.end() || distance < old->second ||
                (distance == old->second && item.first.second < gateways_.at(key))) {
                best[key] = distance; gateways_[key] = item.first.second;
            }
        }
    }
    prefixes_dirty_ = false;
}
std::vector<Network> Gossip::prefixes_for_node(const Network& network, const NodeId& node) const {
    rebuild_prefixes(); const auto found = usable_prefixes_.find(Origin(network, node));
    return found == usable_prefixes_.end() ? std::vector<Network>() : found->second;
}
std::vector<Network> Gossip::advertised_prefixes(const Network& network) const {
    rebuild_prefixes(); std::vector<Network> result;
    for (const auto& item : gateways_) if (item.first.first == network) result.push_back(item.first.second);
    return result;
}
bool Gossip::select_gateway(const Network& network, const Network& prefix, NodeId* gateway) const {
    if (!gateway) return false;
    rebuild_prefixes(); const auto found = gateways_.find(std::make_pair(network, prefix));
    if (found == gateways_.end()) return false;
    *gateway = found->second; return true;
}
std::vector<PathAnnouncement> Gossip::export_to(const Endpoint& peer) const {
    rebuild_prefixes();
    std::map<std::pair<Network, NodeId>, PathAnnouncement> selected;
    const auto allowed = allowed_.find(peer);
    const auto identities = peer_nodes_.find(peer);
    if (!available_.count(peer) || allowed == allowed_.end() || identities == peer_nodes_.end()) return {};
    for (const auto& r : records_) {
        const auto& a = r.announcement;
        const auto peer_node = identities->second.find(a.network);
        if (peer_node == identities->second.end()) continue;
        if (!allowed->second.count(a.network) || a.path.size() >= 64 ||
            std::find(a.path.begin(), a.path.end(), peer_node->second) != a.path.end()) continue;
        auto key = std::make_pair(a.network, a.destination); auto it = selected.find(key);
        if (it == selected.end() || a.path.size() < it->second.path.size() ||
            (a.path.size() == it->second.path.size() && a.path < it->second.path)) selected[key] = a;
    }
    std::vector<PathAnnouncement> result;
    for (auto& item : selected) {
        auto a = item.second;
        const auto local = local_networks_.find(item.first.first);
        if (local == local_networks_.end()) continue;
        a.path.insert(a.path.begin(), local->second);
        a.prefixes = raw_prefixes_.at(item.first);
        public_key(a.network, a.destination, &a.public_key); result.push_back(std::move(a));
    }
    return result;
}
std::vector<PathAnnouncement> Gossip::snapshot() const {
    rebuild_prefixes();
    std::map<std::pair<Network, NodeId>, PathAnnouncement> selected;
    for (const auto& r : records_) selected[{r.announcement.network, r.announcement.destination}] = r.announcement;
    std::vector<PathAnnouncement> result;
    for (const auto& item : selected) {
        auto a = item.second;
        // A representative path is not the authority for destination
        // attributes: use the same latest-origin values as export_to(), even
        // if records are later updated in place or reordered internally.
        a.prefixes = raw_prefixes_.at(item.first);
        public_key(a.network, a.destination, &a.public_key);
        result.push_back(std::move(a));
    }
    return result;
}
