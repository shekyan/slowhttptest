// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// kqueue(2) reactor backend for macOS and the BSDs.
//
// Not an optimisation. The poll() backend measures fine -- about 11% of a core
// at 8000 connections, growing near-linearly -- but on Darwin poll() rejects
// nfds above OPEN_MAX with EINVAL, and OPEN_MAX is a compile-time 10240 that no
// file-descriptor limit raises. Measured: the syscall starts failing at nfds
// 10256. That ceiling is well inside the range needed to stress a modern
// event-driven server, so on this platform kqueue is the only way past it.
//
// One deliberate difference from poll(), and it matters. poll() reports POLLERR
// and POLLHUP whether or not they were requested, so a caller can register
// interest in nothing and still learn that a connection died. kqueue has no
// equivalent: EV_EOF is a flag on a filter's event, not a filter of its own, so
// hearing about a hangup means registering EVFILT_READ -- and doing that for
// slow read, which exists precisely to never drain the socket, would make every
// kevent() return immediately on data the caller has no intention of reading.
// A level-triggered spin, in place of an idle wait.
//
// So this registers exactly what was asked for and nothing more. Slow read
// registers no filters and hears nothing, which is what it wants; it already
// detects a departed peer by asking the TCP state machine once a second, which
// is the reliable method anyway and the reason that sweep exists.
#include "slowhttp/reactor.hpp"

#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace slowhttp {
namespace {

class KqueueReactor : public Reactor {
 public:
  KqueueReactor() : kq_(::kqueue()) {
    if (kq_ < 0) last_error_ = std::string("kqueue() failed: ") +
                               std::strerror(errno);
  }

  ~KqueueReactor() override {
    if (kq_ >= 0) ::close(kq_);
  }

  bool ok() const { return kq_ >= 0; }

  void add(int fd, unsigned interest) override { apply(fd, interest); }
  void modify(int fd, unsigned interest) override { apply(fd, interest); }

  void remove(int fd) override {
    auto it = interest_.find(fd);
    if (it == interest_.end()) return;
    change(fd, EVFILT_READ, EV_DELETE, it->second & kRead);
    change(fd, EVFILT_WRITE, EV_DELETE, it->second & kWrite);
    interest_.erase(it);
  }

  int wait(std::vector<IoEvent>& out,
           std::chrono::milliseconds timeout) override {
    flush_changes();

    // kevent() takes the size of the output array as its cap, so it has to be
    // large enough to be worth a syscall but not sized to every descriptor:
    // only a fraction are ready in any pass.
    if (events_.size() < 1024) events_.resize(1024);

    timespec ts;
    ts.tv_sec = timeout.count() / 1000;
    ts.tv_nsec = static_cast<long>(timeout.count() % 1000) * 1000000L;

    int n = ::kevent(kq_, nullptr, 0, events_.data(),
                     static_cast<int>(events_.size()), &ts);
    if (n < 0) {
      // A signal is not a failure: this is how the tool is stopped.
      if (errno == EINTR) return 0;
      last_error_ = std::string("kevent() failed: ") + std::strerror(errno);
      return -1;
    }

    // One descriptor can produce two events in a single pass -- readable and
    // writable arrive as separate knotes -- so they are merged, or the engine
    // would see the same connection twice and act on it twice.
    merged_.clear();
    for (int i = 0; i < n; ++i) {
      const struct kevent& e = events_[static_cast<std::size_t>(i)];
      const int fd = static_cast<int>(e.ident);

      auto found = merged_.find(fd);
      if (found == merged_.end()) {
        out.push_back(IoEvent{fd, false, false, false});
        found = merged_.emplace(fd, out.size() - 1).first;
      }
      IoEvent& ev = out[found->second];

      // EV_ERROR carries the errno in data and means the registration itself
      // failed; EV_EOF means the peer is done. Both are "this connection is
      // finished" as far as the engine is concerned.
      if (e.flags & EV_ERROR) ev.error = true;
      if (e.flags & EV_EOF) ev.error = true;
      if (e.filter == EVFILT_READ) ev.readable = true;
      if (e.filter == EVFILT_WRITE) ev.writable = true;
    }
    return static_cast<int>(merged_.size());
  }

  // No ceiling worth reporting. Unlike poll() on Darwin, kqueue is bounded only
  // by the process descriptor limit, and 0 is this interface's way of saying
  // "ask the operating system, not me".
  std::size_t max_descriptors() const override { return 0; }

  const std::string& last_error() const override { return last_error_; }

 private:
  void apply(int fd, unsigned interest) {
    const unsigned before = interest_.count(fd) ? interest_[fd] : 0u;
    if (before == interest && interest_.count(fd)) return;
    change(fd, EVFILT_READ, (interest & kRead) ? EV_ADD : EV_DELETE,
           before & kRead);
    change(fd, EVFILT_WRITE, (interest & kWrite) ? EV_ADD : EV_DELETE,
           before & kWrite);
    interest_[fd] = interest;
  }

  // Deleting a filter that was never added fails with ENOENT, which is not an
  // error worth reporting -- but it is worth not asking for, so the previous
  // interest decides whether a delete is even queued.
  void change(int fd, int filter, int flags, unsigned was_registered) {
    if (flags == EV_DELETE && !was_registered) return;
    struct kevent ev;
    EV_SET(&ev, static_cast<uintptr_t>(fd), static_cast<short>(filter),
           static_cast<unsigned short>(flags), 0, 0, nullptr);
    pending_.push_back(ev);
  }

  // Registrations are batched and submitted with the next wait, so opening a
  // thousand connections costs one syscall rather than two thousand.
  void flush_changes() {
    if (pending_.empty()) return;
    struct timespec zero = {0, 0};
    // Errors are reported through the output array, which is discarded here:
    // the only failures possible are deletes of filters already gone, and a
    // registration failure surfaces again as EV_ERROR on the next wait.
    ::kevent(kq_, pending_.data(), static_cast<int>(pending_.size()), nullptr, 0,
             &zero);
    pending_.clear();
  }

  int kq_ = -1;
  std::unordered_map<int, unsigned> interest_;
  std::vector<struct kevent> pending_;
  std::vector<struct kevent> events_;
  std::unordered_map<int, std::size_t> merged_;
  std::string last_error_;
};

}  // namespace

// Defined here and called by the shared factory in reactor_poll.cpp, so the
// choice of backend lives in one place.
std::unique_ptr<Reactor> make_kqueue_reactor() {
  std::unique_ptr<KqueueReactor> r(new KqueueReactor);
  if (!r->ok()) return nullptr;
  return std::unique_ptr<Reactor>(r.release());
}

}  // namespace slowhttp
