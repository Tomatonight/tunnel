#pragma once

// A file capability on the tunnel core gives the parent process
// CAP_NET_ADMIN, but that capability is normally cleared when the core starts
// iproute2 helpers such as `ip`.  Keep the capability in the inheritable and
// ambient sets so those short-lived helpers can configure the interface too.
#if defined(__linux__) && !defined(__ANDROID__)
#include <cerrno>
#include <cstdint>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace tunnel_linux {
inline void prepare_net_admin_child() {
    constexpr unsigned capability = CAP_NET_ADMIN;
    constexpr unsigned helper_capabilities = (1U << CAP_NET_ADMIN) | (1U << CAP_SETPCAP);
    __user_cap_header_struct header{};
    __user_cap_data_struct data[2]{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &header, data) < 0) return;
    const auto word = capability / 32;
    const auto bit = 1U << (capability % 32);
    data[word].inheritable |= bit;
    data[0].inheritable |= helper_capabilities;
    if (syscall(SYS_capset, &header, data) < 0) return;
    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, capability, 0, 0);
}
}
#else
namespace tunnel_linux {
inline void prepare_net_admin_child() {}
}
#endif
