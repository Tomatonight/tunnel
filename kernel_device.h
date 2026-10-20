#pragma once
#include "device.h"
#include <map>

struct KernelPeer {
    Endpoint endpoint;
    const CryptoSession* crypto = nullptr;
    bool tcp = false, ready = false;
    std::vector<Network> networks;
};
struct KernelRoute {
    Network network;
    Endpoint destination;
    IpAddress ip;
    std::vector<Endpoint> hops;
};
struct KernelEnd {
    Network network;
    Endpoint destination;
    const CryptoSession* crypto = nullptr;
    bool ready = false;
};
struct KernelPrefix {
    Network network, prefix;
    Endpoint publisher;
    bool selected = false;
};
struct KernelState {
    std::vector<NetworkConfig> networks;
    std::vector<KernelPeer> peers;
    std::vector<KernelRoute> routes;
    std::vector<KernelEnd> ends;
    std::vector<KernelPrefix> prefixes;
};
struct KernelEvent {
    enum Kind { Tcp = 1, NeedSession = 2, ProbeAck = 3, Rekey = 4 };
    unsigned kind = 0;
    Endpoint peer;
    Network network;
    std::uint64_t token = 0;
    Bytes packet;
};
// An optional data plane, not a PacketDevice raw-IP callback implementation.
// All traffic keys/counters are exclusively owned by the kernel on this backend.
class KernelDataPlane {
public:
    virtual ~KernelDataPlane() {}
    virtual void on_event(std::function<void(KernelEvent)>) = 0;
    virtual void update(const KernelState&) = 0;
    virtual void renew() = 0;
    virtual void shutdown() = 0; // Permanent failure: revoke immediately by closing the owner fd.
    virtual bool probe(const Endpoint&, std::uint64_t) = 0;
    virtual bool receive_tcp(const Endpoint&, const Bytes&) = 0;
    virtual std::map<std::string, std::uint64_t> statistics() const = 0;
};
std::unique_ptr<PacketDevice> open_kernel_device(EventLoop&, const Configure&, const std::string&);
