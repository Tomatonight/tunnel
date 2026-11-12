#include "udp_transport.h"
#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

namespace {
bool blocked(int error) {
#ifdef _WIN32
    return error == WSAEWOULDBLOCK;
#else
    return error == EAGAIN || error == EWOULDBLOCK;
#endif
}
bool interrupted(int error) {
#ifdef _WIN32
    return error == WSAEINTR;
#else
    return error == EINTR;
#endif
}
bool too_large(int error) {
#ifdef _WIN32
    return error == WSAEMSGSIZE;
#else
    return error == EMSGSIZE;
#endif
}
std::runtime_error socket_error(const char* op) {
    return std::runtime_error(std::string(op) + ": " + evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}
constexpr unsigned callback_budget = 64;

bool source_override(const Endpoint& source, unsigned family) {
    return source.ip.family == family && source.ip.unicast();
}


}
SocketSystem::SocketSystem() {
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw std::runtime_error("WSAStartup failed");
#endif
}
SocketSystem::~SocketSystem() {
#ifdef _WIN32
    WSACleanup();
#endif
}
UdpTransport::UdpTransport(EventLoop& loop, const Endpoint& bind, std::size_t max_payload,
                           Receiver receiver, Protector protect, std::size_t queue_limit)
    : family_(bind.ip.family), max_payload_(max_payload), queue_limit_(queue_limit), receiver_(std::move(receiver)) {
    if (max_payload == 0 || max_payload > 65507 || !receiver_ || !queue_limit)
        throw std::invalid_argument("invalid UDP transport limits or receiver");
    socket_ = socket(family_ == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == static_cast<evutil_socket_t>(EVUTIL_INVALID_SOCKET)) throw socket_error("socket");
    try {
        if (evutil_make_socket_nonblocking(socket_) < 0 || evutil_make_socket_closeonexec(socket_) < 0)
            throw socket_error("configure nonblocking socket");
        if (protect && !protect(socket_)) throw std::runtime_error("VPN socket protection failed");
        int one = 1;
#ifdef _WIN32
        if (setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one)) < 0)
            throw socket_error("SO_EXCLUSIVEADDRUSE");
#endif
        if (family_ == 6 && setsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&one), sizeof(one)) < 0)
            throw socket_error("IPV6_V6ONLY");
        int length = 0; auto address = bind.sockaddr_value(&length);
        int bound = ::bind(socket_, reinterpret_cast<const sockaddr*>(&address), length);
#ifdef _WIN32
        // Winsock may finish releasing an exclusive UDP binding shortly after
        // closesocket returns. Bound startup retries permit an immediate restart.
        for (unsigned attempt = 0; bound < 0 && WSAGetLastError() == WSAEADDRINUSE && attempt < 20; ++attempt) {
            Sleep(10);
            bound = ::bind(socket_, reinterpret_cast<const sockaddr*>(&address), length);
        }
#endif
        if (bound < 0)
            throw socket_error(("bind UDP " + bind.str()).c_str());
        read_ = loop.addRead(socket_, [this](evutil_socket_t, short) { read_ready(); });
        write_ = loop.addWrite(socket_, [this](evutil_socket_t, short) { write_ready(); });
        if (!read_ || !write_ || write_->del() < 0) throw std::runtime_error("UDP event registration failed");
    } catch (...) {
        if (read_) read_->del();
        if (write_) write_->del();
        evutil_closesocket(socket_); socket_ = static_cast<evutil_socket_t>(EVUTIL_INVALID_SOCKET); throw;
    }
}
UdpTransport::~UdpTransport() {
    if (read_) read_->del();
    if (write_) write_->del();
    if (socket_ != static_cast<evutil_socket_t>(EVUTIL_INVALID_SOCKET)) evutil_closesocket(socket_);
}
Endpoint UdpTransport::local_address() const {
    sockaddr_storage address{};
    ev_socklen_t length = sizeof(address);
    if (getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &length) < 0) throw socket_error("getsockname");
    return Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&address));
}
UdpTransport::SendResult UdpTransport::send_one(const Endpoint& destination, const Endpoint& source, const Packet& packet) {
    int length; auto address = destination.sockaddr_value(&length);
    const bool force_source = source_override(source, family_);
    int sent = -1;
    if (!force_source) {
        sent = static_cast<int>(sendto(socket_, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                                       reinterpret_cast<const sockaddr*>(&address), length));
    } else {
#ifdef _WIN32
        {
            WSABUF buffer{}; buffer.buf = reinterpret_cast<char*>(const_cast<unsigned char*>(packet.data()));
            buffer.len = static_cast<ULONG>(packet.size());
            char control[128]{};
            WSAMSG message{}; message.name = reinterpret_cast<SOCKADDR*>(&address); message.namelen = length;
            message.lpBuffers = &buffer; message.dwBufferCount = 1;
            message.Control.buf = control; message.Control.len = static_cast<ULONG>(family_ == 4 ? WSA_CMSG_SPACE(sizeof(IN_PKTINFO)) : WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)));
            WSACMSGHDR* cmsg = WSA_CMSG_FIRSTHDR(&message);
            if (family_ == 4) {
                cmsg->cmsg_level = IPPROTO_IP; cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN_PKTINFO));
                IN_PKTINFO info{}; std::memcpy(&info.ipi_addr, source.ip.bytes.data(), sizeof(info.ipi_addr));
                DWORD ifindex = 0; GetBestInterface(info.ipi_addr.S_un.S_addr, &ifindex); info.ipi_ifindex = ifindex;
                std::memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
            } else {
                cmsg->cmsg_level = IPPROTO_IPV6; cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN6_PKTINFO));
                IN6_PKTINFO info{}; std::memcpy(&info.ipi6_addr, source.ip.bytes.data(), sizeof(info.ipi6_addr));
                std::memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
            }
            DWORD bytes = 0;
            const auto result = WSASendMsg(socket_, &message, 0, &bytes, nullptr, nullptr);
            sent = result == 0 ? static_cast<int>(bytes) : -1;
        }
#else
        struct iovec iov{}; iov.iov_base = const_cast<unsigned char*>(packet.data()); iov.iov_len = packet.size();
        struct msghdr message{}; message.msg_name = &address; message.msg_namelen = static_cast<socklen_t>(length);
        message.msg_iov = &iov; message.msg_iovlen = 1;
        bool supported = false;
        // Both IPv4 and IPv6 packet-info records fit comfortably in this
        // control buffer. Keeping the storage fixed also builds on BSDs where
        // `struct in_pktinfo` is not declared even though IP_SENDSRCADDR is.
        char control[128]{};
        message.msg_control = control; message.msg_controllen = sizeof(control);
        cmsghdr* cmsg = CMSG_FIRSTHDR(&message);
        if (family_ == 4) {
#ifdef IP_PKTINFO
            cmsg->cmsg_level = IPPROTO_IP; cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo info{}; std::memcpy(&info.ipi_spec_dst, source.ip.bytes.data(), sizeof(info.ipi_spec_dst));
            std::memcpy(CMSG_DATA(cmsg), &info, sizeof(info)); supported = true;
#elif defined(IP_SENDSRCADDR)
            cmsg->cmsg_level = IPPROTO_IP; cmsg->cmsg_type = IP_SENDSRCADDR;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
            struct in_addr info{}; std::memcpy(&info, source.ip.bytes.data(), sizeof(info));
            std::memcpy(CMSG_DATA(cmsg), &info, sizeof(info)); supported = true;
#endif
        } else {
#ifdef IPV6_PKTINFO
            cmsg->cmsg_level = IPPROTO_IPV6; cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            struct in6_pktinfo info{}; std::memcpy(&info.ipi6_addr, source.ip.bytes.data(), sizeof(info.ipi6_addr));
            std::memcpy(CMSG_DATA(cmsg), &info, sizeof(info)); supported = true;
#endif
        }
        if (supported) sent = static_cast<int>(sendmsg(socket_, &message, 0));
#endif
        if (sent < 0) {
            // A forced source can be unavailable on a particular route (for
            // example after an interface disappears). Retry without packet
            // info so the normal route lookup can choose a reachable source.
            int forced_error = EVUTIL_SOCKET_ERROR();
            if (!forced_error) {
#ifdef _WIN32
                WSASetLastError(WSAEOPNOTSUPP);
#else
                errno = EOPNOTSUPP;
#endif
                forced_error = EVUTIL_SOCKET_ERROR();
            }
            if (!blocked(forced_error) && !interrupted(forced_error) && !too_large(forced_error))
                sent = static_cast<int>(sendto(socket_, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                                               reinterpret_cast<const sockaddr*>(&address), length));
        }
    }
    if (sent >= 0) {
        if (static_cast<std::size_t>(sent) == packet.size()) { ++counters_.sent; return SendResult::Sent; }
        ++counters_.errors; return SendResult::Dropped;
    }
    const int error = EVUTIL_SOCKET_ERROR();
    if (blocked(error) || interrupted(error)) return SendResult::Blocked;
    if (too_large(error)) ++counters_.oversize; else ++counters_.errors;
    return SendResult::Dropped;
}
bool UdpTransport::send(const Endpoint& destination, Packet packet, const Endpoint& source) {
    if (destination.ip.family != family_ || !destination.ip.unicast() || !destination.port)
        throw std::invalid_argument("invalid UDP destination");
    if (packet.size() > max_payload_) { ++counters_.oversize; return false; }
    if (queue_.empty()) {
        const auto result = send_one(destination, source, packet);
        if (result != SendResult::Blocked) return result == SendResult::Sent;
    }
    if (queue_.size() >= queue_limit_) { ++counters_.queue_full; return false; }
    Pending item; item.destination = destination; item.source = source; item.packet = std::move(packet); queue_.push_back(std::move(item));
    if (write_->add() < 0) throw std::runtime_error("cannot enable UDP write event");
    return true;
}
void UdpTransport::write_ready() {
    for (unsigned i = 0; i < callback_budget && !queue_.empty(); ++i) {
        if (send_one(queue_.front().destination, queue_.front().source, queue_.front().packet) == SendResult::Blocked) break;
        queue_.pop_front();
    }
    if (queue_.empty() && write_->del() < 0) throw std::runtime_error("cannot disable UDP write event");
}
void UdpTransport::read_ready() {
    std::array<unsigned char, 65536> buffer;
    for (unsigned i = 0; i < callback_budget; ++i) {
        sockaddr_storage address{}; ev_socklen_t length = sizeof(address);
        const auto size = recvfrom(socket_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                                   reinterpret_cast<sockaddr*>(&address), &length);
        if (size < 0) {
            const int error = EVUTIL_SOCKET_ERROR();
            if (blocked(error)) return;
            if (!interrupted(error)) ++counters_.errors;
            continue;
        }
        if (static_cast<std::size_t>(size) > max_payload_) { ++counters_.oversize; continue; }
        ++counters_.received;
        receiver_(Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&address)), Packet(buffer.begin(), buffer.begin() + size));
    }
}
