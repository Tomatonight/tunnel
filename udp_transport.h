#pragma once
#include "address.h"
#include "event.h"
#include <deque>
#include <vector>

class SocketSystem {
public:
    SocketSystem();
    ~SocketSystem();
    SocketSystem(const SocketSystem&) = delete;
    SocketSystem& operator=(const SocketSystem&) = delete;
};

// One socket per Node. All methods and callbacks run on its event-loop thread.
class UdpTransport {
public:
    using Packet = std::vector<unsigned char>;
    using Receiver = std::function<void(const Endpoint&, Packet)>;
    using Protector = std::function<bool(evutil_socket_t)>; // Android VpnService.protect
    struct Counters {
        std::uint64_t received = 0, sent = 0, oversize = 0, queue_full = 0, errors = 0;
    };
    UdpTransport(EventLoop& loop, const Endpoint& bind, std::size_t max_payload,
                 Receiver receiver, Protector protect = {}, std::size_t queue_limit = 256);
    ~UdpTransport();
    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;
    bool send(const Endpoint& destination, Packet packet);
    Endpoint local_address() const;
    const Counters& counters() const { return counters_; }
    std::size_t pending() const { return queue_.size(); }
private:
    enum class SendResult { Sent, Blocked, Dropped };
    struct Pending { Endpoint destination; Packet packet; };
    SendResult send_one(const Endpoint&, const Packet&);
    void read_ready();
    void write_ready();
    evutil_socket_t socket_ = static_cast<evutil_socket_t>(EVUTIL_INVALID_SOCKET);
    unsigned family_;
    std::size_t max_payload_, queue_limit_;
    Receiver receiver_;
    EventLoop::Handle read_, write_;
    std::deque<Pending> queue_;
    Counters counters_;
};
