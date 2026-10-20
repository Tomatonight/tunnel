#ifndef TUNNEL_EVENT_H
#define TUNNEL_EVENT_H

#include <event2/event.h>

#include <chrono>
#include <functional>
#include <exception>
#include <memory>
#include <vector>

class EventLoop;

class EventHandle : public std::enable_shared_from_this<EventHandle> {
public:
    using Callback = std::function<void(evutil_socket_t, short)>;

    ~EventHandle();

    EventHandle(const EventHandle &) = delete;
    EventHandle &operator=(const EventHandle &) = delete;

    /* Re-enable or disable a registration without destroying its handle. */
    int add();
    int del();
    bool valid() const;

private:
    friend class EventLoop;

    EventHandle(EventLoop *loop, struct event_base *base, evutil_socket_t fd,
                short flags, const struct timeval *timeout, bool persistent,
                Callback callback);

    static void callback_thunk(evutil_socket_t fd, short events, void *arg);
    void detach();

    struct event *event_;
    EventLoop *loop_;
    Callback callback_;
    struct timeval timeout_;
    bool has_timeout_;
};

class EventLoop {
public:
    EventLoop();
    ~EventLoop();

    EventLoop(const EventLoop &) = delete;
    EventLoop &operator=(const EventLoop &) = delete;

    using Handle = std::shared_ptr<EventHandle>;
    using Callback = EventHandle::Callback;

    /* Keep the returned handle alive to retain the event. Owner thread only.
       persistent=false creates a one-shot I/O event. */
    Handle addRead(evutil_socket_t fd, Callback callback,
                   bool persistent = true);
    Handle addWrite(evutil_socket_t fd, Callback callback,
                    bool persistent = true);

    /* Timers use milliseconds and are one-shot unless persistent is true. */
    Handle addTimer(std::chrono::milliseconds timeout, Callback callback,
                    bool persistent = false);

    /* Returns libevent's status: 0 on success, 1 with no events, -1 on error. */
    int run();
    int breakLoop();
    event_base* native_base() const { return base_; }

private:
    friend class EventHandle;

    Handle addEvent(evutil_socket_t fd, short flags,
                    const struct timeval *timeout, bool persistent,
                    Callback callback);

    struct event_base *base_;
    std::vector<std::weak_ptr<EventHandle>> handles_;
    std::exception_ptr callback_error_;
};

#endif  /* TUNNEL_EVENT_H */
