#pragma once
#include "crypto.h"
#include "event.h"
#include "parse_config.h"
#include <functional>
#include <memory>
struct ImportedRoute {
    Network tunnel;
    Network prefix;
    IpAddress source;
};
class PacketDevice {
public:
    using Receiver = std::function<void(Bytes)>;
    virtual ~PacketDevice() {}
    virtual void start(Receiver) = 0;
    virtual bool send(const Bytes&) = 0;
    virtual std::string name() const = 0;
    virtual bool healthy() const { return true; }
    // Owner protocol thread only. Callers must withdraw affected local routes on
    // failure. If healthy() is false, stop all overlay traffic until a new device.
    virtual void set_networks(const std::vector<NetworkConfig>&) {
        throw std::runtime_error("this packet device does not support address updates");
    }
    virtual void set_routes(const std::vector<ImportedRoute>& routes) {
        if (!routes.empty()) throw std::runtime_error("this packet device does not support imported routes");
    }
    virtual void set_exports(const std::vector<AdvertisedRoute>& routes) {
        if (!routes.empty()) throw std::runtime_error("this packet device does not support subnet exports");
    }
};
// For a host-owned device (Android VpnService or another inherited fd): configure
// the complete active address set and return a NEW fd, transferring ownership.
// Return -1 only for an empty set. Called synchronously on the protocol thread.
// Do not close the previous fd; PacketDevice closes it after taking the new one.
// Throw on failure. The device then closes its old fd and stops all traffic.
using NetworkUpdate = std::function<int(const std::vector<NetworkConfig>&)>;
// Full host update. Preserves the old one-argument callback for existing embedders.
using DeviceUpdate = std::function<int(const std::vector<NetworkConfig>&, const std::vector<ImportedRoute>&)>;
// supplied_fd ownership transfers even on failure. With an updater, -1 supports
// waiting for the first address lease without creating a placeholder interface.
std::unique_ptr<PacketDevice> open_tun(EventLoop&, const Configure&, const std::string& name = "", int supplied_fd = -1,
                                     NetworkUpdate update = {}, DeviceUpdate device_update = {});
std::unique_ptr<PacketDevice> open_device(EventLoop&, const Configure&, const std::string& name = "", int supplied_fd = -1,
                                        NetworkUpdate update = {}, DeviceUpdate device_update = {});
