#pragma once
#include "event.h"
#include "udp_transport.h"
#include "crypto.h"
#include <event2/bufferevent.h>
class TcpStream {
public:
    using Receive = std::function<void(const Bytes&)>;
    using Notify = std::function<void()>;
    TcpStream(EventLoop&, evutil_socket_t accepted, UdpTransport::Protector, Receive, Notify connected, Notify closed);
    ~TcpStream();
    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;
    void connect(const Endpoint&);
    bool send(const Bytes&);
    std::size_t pending_bytes() const;
    void close();
private:
    static void read_callback(bufferevent*, void*);
    static void event_callback(bufferevent*, short, void*);
    bufferevent* stream_ = nullptr;
    Receive receive_;
    Notify connected_, closed_;
    UdpTransport::Protector protect_;
    bool closed_flag_ = false;
};
class TcpListener {
public:
    using Accept = std::function<void(evutil_socket_t)>;
    TcpListener(EventLoop&, const Endpoint&, Accept, UdpTransport::Protector = {});
    ~TcpListener();
private:
    evutil_socket_t socket_ = EVUTIL_INVALID_SOCKET;
    EventLoop::Handle event_;
};
