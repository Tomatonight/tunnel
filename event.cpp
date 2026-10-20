#include "event.h"

#include <cstddef>
#include <utility>
#include <stdexcept>
#include <algorithm>

EventHandle::EventHandle(EventLoop *loop, struct event_base *base,
                         evutil_socket_t fd, short flags,
                         const struct timeval *timeout, bool persistent,
                         Callback callback)
    : event_(nullptr),
      loop_(loop),
      callback_(std::move(callback)),
      timeout_(),
      has_timeout_(timeout != nullptr) {
    if (timeout != nullptr) {
        timeout_ = *timeout;
    }
    if (persistent) {
        flags = static_cast<short>(flags | EV_PERSIST);
    }
    event_ = event_new(base, fd, flags, &EventHandle::callback_thunk, this);
}

EventHandle::~EventHandle() {
    detach();
}

void EventHandle::callback_thunk(evutil_socket_t fd, short events, void *arg) {
    EventHandle *handle = static_cast<EventHandle *>(arg);
    if (handle == nullptr || !handle->callback_) {
        return;
    }

    // Retain the handle through the catch block even if its callback releases it.
    std::shared_ptr<EventHandle> keep_alive;
    // A C callback must not let a C++ exception cross the libevent boundary.
    try {
        keep_alive = handle->shared_from_this();
        handle->callback_(fd, events);
    } catch (...) {
        if (handle->loop_ != nullptr) {
            handle->loop_->callback_error_ = std::current_exception();
            handle->loop_->breakLoop();
        }
    }
}

int EventHandle::add() {
    if (event_ == nullptr || loop_ == nullptr) {
        return -1;
    }
    return event_add(event_, has_timeout_ ? &timeout_ : nullptr);
}

int EventHandle::del() {
    if (event_ == nullptr) {
        return -1;
    }
    return event_del(event_);
}

bool EventHandle::valid() const {
    return event_ != nullptr && loop_ != nullptr;
}

void EventHandle::detach() {
    if (event_ != nullptr) {
        event_free(event_);
        event_ = nullptr;
    }
    loop_ = nullptr;
}

EventLoop::EventLoop() : base_(event_base_new()), handles_() {
    if (!base_) throw std::runtime_error("cannot create libevent loop");
}

EventLoop::~EventLoop() {
    for (const auto &weak : handles_) {
        const auto handle = weak.lock();
        if (handle != nullptr) {
            handle->detach();
        }
    }
    handles_.clear();
    if (base_ != nullptr) {
        event_base_free(base_);
        base_ = nullptr;
    }
}

EventLoop::Handle EventLoop::addEvent(evutil_socket_t fd, short flags,
                                      const struct timeval *timeout,
                                      bool persistent, Callback callback) {
    if (base_ == nullptr || !callback) {
        return Handle();
    }

    Handle handle(new EventHandle(this, base_, fd, flags, timeout, persistent,
                                  std::move(callback)));
    if (!handle->valid() || handle->add() != 0) {
        return Handle();
    }
    handles_.erase(std::remove_if(handles_.begin(), handles_.end(),
        [](const std::weak_ptr<EventHandle>& weak) { return weak.expired(); }), handles_.end());
    handles_.push_back(handle);
    return handle;
}

EventLoop::Handle EventLoop::addRead(evutil_socket_t fd, Callback callback,
                                     bool persistent) {
    return addEvent(fd, EV_READ, nullptr, persistent, std::move(callback));
}

EventLoop::Handle EventLoop::addWrite(evutil_socket_t fd, Callback callback,
                                      bool persistent) {
    return addEvent(fd, EV_WRITE, nullptr, persistent, std::move(callback));
}

EventLoop::Handle EventLoop::addTimer(std::chrono::milliseconds timeout,
                                      Callback callback, bool persistent) {
    if (timeout.count() < 0) {
        return Handle();
    }

    const long long total_ms = timeout.count();
    struct timeval interval;
    interval.tv_sec = static_cast<decltype(interval.tv_sec)>(total_ms / 1000);
    interval.tv_usec = static_cast<decltype(interval.tv_usec)>(
        (total_ms % 1000) * 1000);
    return addEvent(-1, EV_TIMEOUT, &interval, persistent,
                    std::move(callback));
}

int EventLoop::run() {
    if (base_ == nullptr) {
        return -1;
    }
    callback_error_ = nullptr;
    const int result = event_base_dispatch(base_);
    if (callback_error_) std::rethrow_exception(callback_error_);
    return result;
}

int EventLoop::breakLoop() {
    if (base_ == nullptr) {
        return -1;
    }
    return event_base_loopbreak(base_);
}
