// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Portable poll(2) reactor backend, so the tool builds and runs identically on
// Linux, macOS and BSD.
//
// Its limit is not really the per-call O(n) scan -- measured, that costs about
// 11% of a core at 8000 connections. It is that poll() has a hard ceiling on
// some platforms (Darwin: a fixed OPEN_MAX of 10240, immovable by ulimit), which
// is well inside the range needed to stress a modern event-driven server. epoll
// and kqueue backends implementing this same interface are what get past it.
#include "slowhttp/reactor.hpp"

#include <limits.h>
#include <poll.h>
#include <time.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

namespace slowhttp {
namespace {

// How many descriptors poll(2) will accept on this platform.
//
// Darwin rejects nfds > OPEN_MAX with EINVAL, and its OPEN_MAX is a
// compile-time 10240 -- a hard wall, not a tunable: raising the file descriptor
// limit does nothing for it. Measured: the syscall starts failing at nfds 10256.
// Elsewhere poll() is bounded only by the process descriptor limit.
std::size_t poll_capacity() {
#if defined(__APPLE__) && defined(OPEN_MAX)
  return static_cast<std::size_t>(OPEN_MAX);
#else
  return 0;
#endif
}

short to_poll_events(unsigned interest) {
  short e = 0;
  if (interest & kRead) e |= POLLIN;
  if (interest & kWrite) e |= POLLOUT;
  return e;
}

class PollReactor : public Reactor {
 public:
  void add(int fd, unsigned interest) override {
    auto it = index_.find(fd);
    if (it != index_.end()) {
      fds_[it->second].events = to_poll_events(interest);
      return;
    }
    pollfd p{};
    p.fd = fd;
    p.events = to_poll_events(interest);
    p.revents = 0;
    index_[fd] = fds_.size();
    fds_.push_back(p);
  }

  void modify(int fd, unsigned interest) override { add(fd, interest); }

  void remove(int fd) override {
    auto it = index_.find(fd);
    if (it == index_.end()) return;
    std::size_t i = it->second;
    std::size_t last = fds_.size() - 1;
    if (i != last) {
      fds_[i] = fds_[last];
      index_[fds_[i].fd] = i;
    }
    fds_.pop_back();
    index_.erase(it);
  }

  int wait(std::vector<IoEvent>& out, std::chrono::milliseconds timeout) override {
    if (fds_.empty()) {
      // Nothing registered yet: sleep so the engine's timers still advance.
      if (timeout.count() > 0) {
        timespec ts;
        ts.tv_sec = timeout.count() / 1000;
        ts.tv_nsec = static_cast<long>(timeout.count() % 1000) * 1000000L;
        ::nanosleep(&ts, nullptr);
      }
      return 0;
    }
    int n = ::poll(fds_.data(), static_cast<nfds_t>(fds_.size()),
                   static_cast<int>(timeout.count()));
    if (n < 0) {
      // A signal is not a failure: SIGINT arriving mid-wait is the normal way
      // this tool is stopped, and the loop should just come round again.
      if (errno == EINTR) return 0;
      last_error_ = describe_failure(errno, fds_.size());
      return -1;
    }
    if (n == 0) return 0;
    int produced = 0;
    for (auto& p : fds_) {
      if (p.revents == 0) continue;
      IoEvent ev;
      ev.fd = p.fd;
      ev.readable = (p.revents & POLLIN) != 0;
      ev.writable = (p.revents & POLLOUT) != 0;
      ev.error = (p.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
      out.push_back(ev);
      if (++produced == n) break;
    }
    return produced;
  }

  const char* name() const override { return "poll"; }

  std::size_t max_descriptors() const override { return poll_capacity(); }

  const std::string& last_error() const override { return last_error_; }

 private:
  // Says what to do about it, not just what went wrong. EINVAL here is almost
  // always the platform ceiling rather than a bug in the arguments.
  static std::string describe_failure(int err, std::size_t nfds) {
    char buf[320];
    const std::size_t cap = poll_capacity();
    if (err == EINVAL && cap > 0 && nfds > cap) {
      std::snprintf(buf, sizeof(buf),
                    "poll() cannot watch %zu descriptors on this platform: the "
                    "limit is %zu (OPEN_MAX) and no file-descriptor limit raises "
                    "it. Lower -c, or use a build with the epoll/kqueue backend.",
                    nfds, cap);
    } else {
      std::snprintf(buf, sizeof(buf), "poll() failed with %zu descriptors: %s",
                    nfds, std::strerror(err));
    }
    return buf;
  }

  std::vector<pollfd> fds_;
  std::unordered_map<int, std::size_t> index_;
  std::string last_error_;
};

}  // namespace

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
#define SLOWHTTP_HAVE_KQUEUE 1
std::unique_ptr<Reactor> make_kqueue_reactor();
#endif

#if defined(__linux__)
#define SLOWHTTP_HAVE_EPOLL 1
std::unique_ptr<Reactor> make_epoll_reactor();
#endif

// kqueue on the BSDs, epoll on Linux, poll everywhere else.
//
// SLOWHTTP_REACTOR=poll forces the portable backend. That exists so the two can
// be compared on the same machine and the same target -- a backend that is only
// ever exercised on one platform is a backend nobody has checked against the
// other, and every behavioural difference between these two has to be found by
// running them side by side. e2e_http2_poll exercises it on every platform for
// the same reason: poll() is now the default nowhere, and a backend nothing
// runs is a backend that rots.
std::unique_ptr<Reactor> Reactor::create() {
#if defined(SLOWHTTP_HAVE_KQUEUE) || defined(SLOWHTTP_HAVE_EPOLL)
  const char* forced = ::getenv("SLOWHTTP_REACTOR");
  const bool want_poll = forced && std::strcmp(forced, "poll") == 0;
#endif
#ifdef SLOWHTTP_HAVE_KQUEUE
  if (!want_poll) {
    if (auto kq = make_kqueue_reactor()) return kq;
    // Falling back rather than failing: a machine that cannot create a kqueue
    // can still run the test, just with the old ceiling.
  }
#endif
#ifdef SLOWHTTP_HAVE_EPOLL
  if (!want_poll) {
    // Same fallback reasoning: a container or seccomp policy that refuses
    // epoll_create1 should degrade to poll() rather than refuse to run. On
    // Linux poll() has no OPEN_MAX ceiling, so the fallback is a slower run
    // rather than a smaller one.
    if (auto ep = make_epoll_reactor()) return ep;
  }
#endif
  return std::unique_ptr<Reactor>(new PollReactor());
}

}  // namespace slowhttp
