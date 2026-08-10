// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Portable poll(2) reactor backend. This is the M0 default so the tool builds and
// runs identically on Linux, macOS and BSD. epoll/kqueue backends implementing the
// same Reactor interface land in M1 to scale past poll()'s per-call O(n) scan.
#include "slowhttp/reactor.hpp"

#include <poll.h>
#include <time.h>

#include <cstddef>
#include <unordered_map>

namespace slowhttp {
namespace {

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
    if (n <= 0) return 0;
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

 private:
  std::vector<pollfd> fds_;
  std::unordered_map<int, std::size_t> index_;
};

}  // namespace

std::unique_ptr<Reactor> Reactor::create() {
  return std::unique_ptr<Reactor>(new PollReactor());
}

}  // namespace slowhttp
