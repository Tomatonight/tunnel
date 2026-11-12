#include "tcp_transport.h"
#include <event2/buffer.h>
#include <event2/util.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
namespace {
constexpr std::size_t queue_limit = 1024 * 1024;
constexpr evutil_socket_t invalid_socket = static_cast<evutil_socket_t>(EVUTIL_INVALID_SOCKET);
void configure_socket(evutil_socket_t socket) {
    if (evutil_make_socket_nonblocking(socket) < 0 || evutil_make_socket_closeonexec(socket) < 0)
        throw std::runtime_error("TCP socket configuration failed");
    int one = 1;
    setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
}
std::string socket_error_reason() {
    const int code = EVUTIL_SOCKET_ERROR();
    const char* text = evutil_socket_error_to_string(code);
    if (!code || !text) return "TCP socket error";
    return std::string("TCP socket error ") + std::to_string(code) + ": " + text;
}
}
TcpStream::TcpStream(EventLoop& loop, evutil_socket_t accepted, UdpTransport::Protector protect,
                     Receive receive, Notify connected, Notify closed)
    : receive_(std::move(receive)), connected_(std::move(connected)), closed_(std::move(closed)), protect_(std::move(protect)) {
    try {
        if (accepted != invalid_socket) {
            configure_socket(accepted);
            sockaddr_storage address{};
            ev_socklen_t length = sizeof(address);
            if (getpeername(accepted, reinterpret_cast<sockaddr*>(&address), &length) == 0)
                peer_address_ = Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&address));
            if (protect_ && !protect_(accepted)) throw std::runtime_error("TCP protection failed");
        }
        stream_ = bufferevent_socket_new(loop.native_base(), accepted, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        if (!stream_) throw std::runtime_error("TCP event allocation");
        bufferevent_setcb(stream_, read_callback, nullptr, event_callback, this);
        bufferevent_setwatermark(stream_, EV_READ, 0, queue_limit);
        if (bufferevent_enable(stream_, EV_READ | EV_WRITE) < 0)
            throw std::runtime_error("TCP event enable failed");
    } catch (...) {
        // Once bufferevent_socket_new succeeds it owns the accepted descriptor
        // (BEV_OPT_CLOSE_ON_FREE).  Free it on constructor failure instead of
        // leaking the bufferevent or closing the descriptor behind its back.
        if (stream_) {
            bufferevent_free(stream_);
            stream_ = nullptr;
        } else if (accepted != invalid_socket) {
            evutil_closesocket(accepted);
        }
        throw;
    }
}
TcpStream::~TcpStream() { if (stream_) bufferevent_free(stream_); }
void TcpStream::connect(const Endpoint& endpoint) {
    auto socket = ::socket(endpoint.ip.family == 4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (socket == EVUTIL_INVALID_SOCKET) throw std::runtime_error("TCP socket creation");
    try {
        configure_socket(socket);
        if (protect_ && !protect_(socket)) throw std::runtime_error("TCP protection failed");
    } catch (...) { evutil_closesocket(socket); throw; }
    if (bufferevent_setfd(stream_, socket) < 0) { evutil_closesocket(socket); throw std::runtime_error("TCP attach"); }
    int length; const auto address = endpoint.sockaddr_value(&length);
    if (bufferevent_socket_connect(stream_, reinterpret_cast<const sockaddr*>(&address), length) < 0)
        close("TCP connect setup failed");
}
Endpoint TcpStream::local_address() const {
    const auto socket = bufferevent_getfd(stream_);
    if (socket == invalid_socket) throw std::runtime_error("TCP local address unavailable");
    sockaddr_storage address{};
    ev_socklen_t length = sizeof(address);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) < 0)
        throw std::runtime_error("TCP local address unavailable");
    return Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&address));
}
Endpoint TcpStream::peer_address() const {
    if (peer_address_.port) return peer_address_;
    const auto socket = bufferevent_getfd(stream_);
    if (socket == invalid_socket) throw std::runtime_error("TCP peer address unavailable");
    sockaddr_storage address{};
    ev_socklen_t length = sizeof(address);
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&address), &length) < 0)
        throw std::runtime_error("TCP peer address unavailable");
    return Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&address));
}
bool TcpStream::send(const Bytes& bytes) {
    if (closed_flag_) return false;
    const auto pending = evbuffer_get_length(bufferevent_get_output(stream_));
    if (pending > queue_limit || bytes.size() > queue_limit - pending) {
        close("TCP output queue limit exceeded");
        return false;
    }
    if (bufferevent_write(stream_, bytes.data(), bytes.size()) < 0) {
        close("TCP output write failed");
        return false;
    }
    return true;
}
std::size_t TcpStream::pending_bytes() const {
    return stream_ ? evbuffer_get_length(bufferevent_get_output(stream_)) : 0;
}
void TcpStream::close(const std::string& reason) {
    if (closed_flag_) return;
    close_reason_ = reason.empty() ? "TCP connection closed" : reason;
    closed_flag_ = true; bufferevent_disable(stream_, EV_READ | EV_WRITE);
    auto fd = bufferevent_getfd(stream_);
    if (fd != invalid_socket) {
#ifdef _WIN32
        shutdown(fd, SD_BOTH);
#else
        shutdown(fd, SHUT_RDWR);
#endif
    }
    if (closed_) closed_();
}
void TcpStream::read_callback(bufferevent* stream, void* argument) {
    auto& self = *static_cast<TcpStream*>(argument);
    try {
        const auto size = std::min<std::size_t>(65536, evbuffer_get_length(bufferevent_get_input(stream)));
        Bytes bytes(size); evbuffer_remove(bufferevent_get_input(stream), bytes.data(), size);
        self.receive_(bytes);
    } catch (const std::exception& error) {
        self.close(std::string("TCP receive callback failed: ") + error.what());
    } catch (...) {
        self.close("TCP receive callback failed");
    }
}
void TcpStream::event_callback(bufferevent*, short events, void* argument) {
    auto& self = *static_cast<TcpStream*>(argument);
    try {
        if (events & BEV_EVENT_TIMEOUT) self.close("TCP connection timeout");
        else if (events & BEV_EVENT_ERROR) self.close(socket_error_reason());
        else if (events & BEV_EVENT_EOF) self.close("peer closed TCP connection");
        else if (events & BEV_EVENT_CONNECTED) self.connected_();
    } catch (const std::exception& error) {
        self.close(std::string("TCP event callback failed: ") + error.what());
    } catch (...) {
        self.close("TCP event callback failed");
    }
}
TcpListener::TcpListener(EventLoop& loop, const Endpoint& endpoint, Accept accept_callback, UdpTransport::Protector protect) {
    socket_ = socket(endpoint.ip.family == 4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == invalid_socket) throw std::runtime_error("TCP listener creation");
    try {
        configure_socket(socket_); int one = 1;
        if (protect && !protect(socket_)) throw std::runtime_error("TCP listener protection failed");
#ifdef _WIN32
        setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
#else
        setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
        if (endpoint.ip.family == 6)
            setsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&one), sizeof(one));
        int length; const auto address = endpoint.sockaddr_value(&length);
        if (bind(socket_, reinterpret_cast<const sockaddr*>(&address), length) < 0 || listen(socket_, 64) < 0)
            throw std::runtime_error("TCP bind/listen failed");
        event_ = loop.addRead(socket_, [this, accept_callback](evutil_socket_t, short) {
            for (unsigned i = 0; i < 16; ++i) {
                const auto fd = accept(socket_, nullptr, nullptr);
                if (fd == EVUTIL_INVALID_SOCKET) break;
                accept_callback(fd); // callback takes ownership, including on failure
            }
        });
        if (!event_) throw std::runtime_error("TCP event registration failed");
    } catch (...) { evutil_closesocket(socket_); throw; }
}
TcpListener::~TcpListener() { event_.reset(); if (socket_ != invalid_socket) evutil_closesocket(socket_); }
