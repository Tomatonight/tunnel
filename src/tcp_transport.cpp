#include "tcp_transport.h"
#include <event2/buffer.h>
#include <cerrno>
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
}
TcpStream::TcpStream(EventLoop& loop, evutil_socket_t accepted, UdpTransport::Protector protect,
                     Receive receive, Notify connected, Notify closed)
    : receive_(std::move(receive)), connected_(std::move(connected)), closed_(std::move(closed)), protect_(std::move(protect)) {
    try {
        if (accepted != invalid_socket) {
            configure_socket(accepted);
            if (protect_ && !protect_(accepted)) throw std::runtime_error("TCP protection failed");
        }
        stream_ = bufferevent_socket_new(loop.native_base(), accepted, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        if (!stream_) throw std::runtime_error("TCP event allocation");
        bufferevent_setcb(stream_, read_callback, nullptr, event_callback, this);
        bufferevent_setwatermark(stream_, EV_READ, 0, queue_limit);
        bufferevent_enable(stream_, EV_READ | EV_WRITE);
    } catch (...) { if (accepted != invalid_socket) evutil_closesocket(accepted); throw; }
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
    if (bufferevent_socket_connect(stream_, reinterpret_cast<const sockaddr*>(&address), length) < 0) close();
}
bool TcpStream::send(const Bytes& bytes) {
    if (closed_flag_) return false;
    if (bytes.size() + evbuffer_get_length(bufferevent_get_output(stream_)) > queue_limit ||
        bufferevent_write(stream_, bytes.data(), bytes.size()) < 0) { close(); return false; }
    return true;
}
std::size_t TcpStream::pending_bytes() const {
    return stream_ ? evbuffer_get_length(bufferevent_get_output(stream_)) : 0;
}
void TcpStream::close() {
    if (closed_flag_) return;
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
    } catch (...) { self.close(); }
}
void TcpStream::event_callback(bufferevent*, short events, void* argument) {
    auto& self = *static_cast<TcpStream*>(argument);
    try {
        if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) self.close();
        else if (events & BEV_EVENT_CONNECTED) self.connected_();
    } catch (...) { self.close(); }
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
    } catch (...) { evutil_closesocket(socket_); throw; }
}
TcpListener::~TcpListener() { event_.reset(); if (socket_ != invalid_socket) evutil_closesocket(socket_); }
