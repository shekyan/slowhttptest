// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_REACTOR_HPP_
#define SLOWHTTP_REACTOR_HPP_

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace slowhttp {

// Readiness interest bitmask.
enum Interest : unsigned { kNone = 0u, kRead = 1u, kWrite = 2u };

struct IoEvent {
  int fd = -1;
  bool readable = false;
  bool writable = false;
  bool error = false;
};

// Readiness multiplexer abstraction. M0 ships a portable poll() backend that
// compiles on Linux/macOS/BSD; the whole point of this interface is that epoll
// (Linux) and kqueue (macOS/BSD) backends drop in for M1 to scale past poll()'s
// O(n) scan without touching the engine.
class Reactor {
 public:
  virtual ~Reactor() = default;

  virtual void add(int fd, unsigned interest) = 0;
  virtual void modify(int fd, unsigned interest) = 0;
  virtual void remove(int fd) = 0;

  // Block up to `timeout`; append ready events to `out`.
  //
  // Returns the number appended, 0 on timeout, and -1 on a *fatal* error. The
  // distinction matters more than it looks: a caller that treats failure as
  // "nothing happened" will call straight back in, and a reactor that cannot
  // wait then spins at the speed of the syscall forever, burning a core in
  // silence. Callers must stop on -1, not retry.
  virtual int wait(std::vector<IoEvent>& out, std::chrono::milliseconds timeout) = 0;

  // Largest number of descriptors this backend can watch at once, or 0 when the
  // only limit is the process file-descriptor limit. Lets the engine refuse an
  // impossible connection count up front instead of failing 10,000 sockets in.
  // Which backend this actually is. Reported by -V, which used to print "poll"
  // unconditionally -- so on a machine running kqueue the version output named
  // the wrong backend while correctly reporting that backend's descriptor
  // ceiling. A diagnostic that contradicts itself is worse than none, and -V
  // output is what arrives in bug reports.
  virtual const char* name() const = 0;

  virtual std::size_t max_descriptors() const = 0;

  // Why the last wait() returned -1. Empty if nothing has failed.
  virtual const std::string& last_error() const = 0;

  // Platform default backend (poll()).
  static std::unique_ptr<Reactor> create();
};

}  // namespace slowhttp

#endif  // SLOWHTTP_REACTOR_HPP_
