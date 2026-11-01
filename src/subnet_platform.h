#pragma once
#include "device.h"

// Pure validation is also used for Android host-owned descriptors.
std::vector<ImportedRoute> checked_imports(const Configure&, const std::vector<NetworkConfig>&,
                                         const std::vector<ImportedRoute>&);
bool same_imports(const std::vector<ImportedRoute>&, const std::vector<ImportedRoute>&);
// Route probes must not hit a local host route or IPv6 subnet-router anycast.
std::vector<IpAddress> subnet_probe_addresses(const Network&, const std::vector<IpAddress>& local_addresses);
// OS resource owner. Never replaces somebody else's route or global NAT table.
class SubnetPlatform {
public:
    SubnetPlatform(const std::string& interface_name, const Configure&);
    ~SubnetPlatform();
    void set_routes(const std::vector<ImportedRoute>&);
    void set_exports(const std::vector<AdvertisedRoute>&);
    void clear(); // Explicit shutdown reports failures; destructor is best effort.
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
