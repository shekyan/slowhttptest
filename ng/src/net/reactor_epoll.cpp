// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// epoll(7) reactor backend for Linux.
//
// The reason here is different from the kqueue one, and weaker. On Darwin
// poll() refuses nfds above a compile-time OPEN_MAX of 10240, so kqueue is the
// only way past that ceiling. Linux has no such limit: poll() there is bounded
// by RLIMIT_NOFILE and by its own O(n) scan, and the scan is the whole argument
// for this file.
//
// That scan cost had never been measured on Linux when this was written, and
// DESIGN.md said so. What was measured, on macOS, is that the cost is real but
// modest -- about 11% of a core at 8000 connections, growing near-linearly --
// and that the tool's own work is dominated by waiting rather than scanning. So
// this is an efficiency change on the platform where most runs happen, not a
// capability change, and it should be judged against a measurement rather than
// against the reputation of poll().
//
// Two deliberate choices:
//
// Level-triggered, no EPOLLET. The engine leaves sockets partially drained on
// purpose -- on_readable() stops at a per-dispatch budget and expects the fd to
// be reported again on the next wakeup. Edge-triggered would strand those
// connections until more data happened to arrive, which for slow read is never.
//
// Registrations are applied immediately rather than batched. kqueue can queue
// changes and submit them with the next wait, so opening a thousand connections
// costs one syscall; epoll_ctl has no equivalent and takes one syscall per
// descriptor either way. Pretending otherwise would add a layer that saves
// nothing.
#include "slowhttp/reactor.hpp"

#include <sys/epoll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace slowhttp {
namespace {

class EpollReactor : public Reactor {
 public:
  EpollReactor() : ep_(::epoll_create1(EPOLL_CLOEXEC)) {
    if (ep_ < 0)
      last_error_ = std::string("epoll_create1() failed: ") +
                    std::strerror(errno);
  }

  ~EpollReactor() override {
    if (ep_ >= 0) ::close(ep_);
  }

  bool ok() const { return ep_ >= 0; }

  void add(int fd, unsigned interest) override { apply(fd, interest); }
  void modify(int fd, unsigned interest) override { apply(fd, interest); }

  void remove(int fd) override {
    auto it = registered_.find(fd);
    if (it == registered_.end()) return;
    // A descriptor already closed is gone from the set automatically, so EBADF
    // and ENOENT here are expected rather than failures worth reporting.
    ::epoll_ctl(ep_, EPOLL_CTL_DEL, fd, nullptr);
    registered_.erase(it);
  }

  int wait(std::vector<IoEvent>& out,
           std::chrono::milliseconds timeout) override {
    // Sized like the kqueue backend's: big enough to be worth a syscall, not
    // sized to every descriptor, because only a fraction are ready in a pass.
    if (events_.size() < 1024) events_.resize(1024);

    int ms = static_cast<int>(timeout.count());
    if (ms < 0) ms = 0;

    const int n = ::epoll_wait(ep_, events_.data(),
                               static_cast<int>(events_.size()), ms);
    if (n < 0) {
      // A signal is not a failure: this is how the tool is stopped.
      if (errno == EINTR) return 0;
      last_error_ = std::string("epoll_wait() failed: ") + std::strerror(errno);
      return -1;
    }

    // No merging pass is needed. epoll reports one event per descriptor with
    // the ready conditions or-ed together, unlike kqueue where readable and
    // writable arrive as separate knotes for the same fd.
    for (int i = 0; i < n; ++i) {
      const epoll_event& e = events_[static_cast<std::size_t>(i)];
      IoEvent ev;
      ev.fd = e.data.fd;
      ev.readable = (e.events & EPOLLIN) != 0;
      ev.writable = (e.events & EPOLLOUT) != 0;
      // Reported whether or not they were asked for, exactly as poll() does --
      // and unlike kqueue, which has no equivalent and forced that backend to
      // stay silent for a caller registering no interest. So slow read, which
      // registers nothing, still learns here that a peer has gone.
      ev.error = (e.events & (EPOLLERR | EPOLLHUP)) != 0;
      out.push_back(ev);
    }
    return n;
  }

  const char* name() const override { return "epoll"; }

  // Bounded by RLIMIT_NOFILE rather than by anything this backend imposes; 0 is
  // this interface's way of saying "ask the operating system, not me".
  std::size_t max_descriptors() const override { return 0; }

  const std::string& last_error() const override { return last_error_; }

 private:
  void apply(int fd, unsigned interest) {
    epoll_event ev{};
    ev.events = 0;
    if (interest & kRead) ev.events |= EPOLLIN;
    if (interest & kWrite) ev.events |= EPOLLOUT;
    ev.data.fd = fd;

    auto it = registered_.find(fd);
    if (it == registered_.end()) {
      if (::epoll_ctl(ep_, EPOLL_CTL_ADD, fd, &ev) == 0) {
        registered_[fd] = interest;
      } else if (errno == EEXIST) {
        // Left over from a descriptor number reused before its removal was
        // seen. Modify is the correct repair, and the map is corrected too.
        if (::epoll_ctl(ep_, EPOLL_CTL_MOD, fd, &ev) == 0)
          registered_[fd] = interest;
      } else {
        last_error_ = std::string("epoll_ctl(ADD) failed: ") +
                      std::strerror(errno);
      }
      return;
    }

    if (it->second == interest) return;  // nothing to say
    if (::epoll_ctl(ep_, EPOLL_CTL_MOD, fd, &ev) == 0) {
      it->second = interest;
    } else {
      last_error_ = std::string("epoll_ctl(MOD) failed: ") +
                    std::strerror(errno);
    }
  }

  int ep_ = -1;
  std::unordered_map<int, unsigned> registered_;
  std::vector<epoll_event> events_;
  std::string last_error_;
};

}  // namespace

// Defined here and called by the shared factory in reactor_poll.cpp, so the
// choice of backend lives in one place.
std::unique_ptr<Reactor> make_epoll_reactor() {
  std::unique_ptr<EpollReactor> r(new EpollReactor);
  if (!r->ok()) return nullptr;
  return std::unique_ptr<Reactor>(r.release());
}

}  // namespace slowhttp
