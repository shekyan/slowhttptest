// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_REACTOR_HPP_
#define SLOWHTTP_REACTOR_HPP_

#include <chrono>
#include <memory>
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

  // Block up to `timeout`; append ready events to `out`; return count appended.
  virtual int wait(std::vector<IoEvent>& out, std::chrono::milliseconds timeout) = 0;

  // Platform default backend (poll() in M0).
  static std::unique_ptr<Reactor> create();
};

}  // namespace slowhttp

#endif  // SLOWHTTP_REACTOR_HPP_
