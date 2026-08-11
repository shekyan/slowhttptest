// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Reactor contract tests, with one case that exists because of a real bug:
// wait() used to return 0 both when nothing happened and when poll(2) failed.
// On macOS poll() rejects more than OPEN_MAX descriptors with EINVAL, so past
// ~10k connections every wait failed, every failure looked like "no events",
// and the engine spun at ~4.5 million iterations a second -- burning a core,
// holding almost no connections, and printing nothing at all.
//
// The contract that prevents that: 0 means timeout, -1 means stop.
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <vector>

#include "slowhttp/reactor.hpp"

using slowhttp::IoEvent;
using slowhttp::Reactor;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

int main() {
  auto r = Reactor::create();
  std::vector<IoEvent> events;

  // An empty reactor must still honour the timeout, or the engine's timers
  // would run in a busy loop before the first connection is opened.
  {
    const auto t0 = std::chrono::steady_clock::now();
    const int n = r->wait(events, std::chrono::milliseconds(60));
    const auto slept = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - t0)
                           .count();
    check(n == 0, "empty reactor reports a timeout, not an error");
    check(events.empty(), "empty reactor produces no events");
    check(slept >= 40, "empty reactor actually waits rather than spinning");
  }

  // A zero timeout is a poll, not a failure.
  {
    events.clear();
    check(r->wait(events, std::chrono::milliseconds(0)) == 0,
          "zero timeout returns promptly and reports no events");
  }

  // A registered but idle descriptor: still a timeout, still not an error.
  {
    int fds[2];
    check(::pipe(fds) == 0, "pipe created for the idle-descriptor case");
    r->add(fds[0], slowhttp::kRead);
    events.clear();
    const int n = r->wait(events, std::chrono::milliseconds(50));
    check(n == 0, "an idle descriptor reports a timeout");
    check(r->last_error().empty(), "a timeout is not recorded as an error");

    // ...and a readable one is reported exactly once.
    check(::write(fds[1], "x", 1) == 1, "wrote a byte to the pipe");
    events.clear();
    const int m = r->wait(events, std::chrono::milliseconds(50));
    check(m == 1 && events.size() == 1, "a ready descriptor is reported");
    check(events[0].fd == fds[0] && events[0].readable,
          "the right descriptor is reported readable");

    r->remove(fds[0]);
    ::close(fds[0]);
    ::close(fds[1]);
  }

  // The capacity the engine uses to refuse an impossible -c up front. Either a
  // real ceiling, or 0 meaning "only the file descriptor limit applies".
  {
    const std::size_t cap = r->max_descriptors();
    check(cap == 0 || cap >= 1024,
          "a reported ceiling is a plausible one, not a tiny number");
#if defined(__APPLE__)
    // Darwin's is a compile-time OPEN_MAX that no ulimit raises, so it must be
    // reported -- this is exactly the platform where the silent spin happened.
    check(cap > 0, "macOS reports its fixed poll() ceiling");
#endif
  }

  if (failures == 0) {
    std::printf("reactor: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "reactor: %d check(s) failed\n", failures);
  return 1;
}
