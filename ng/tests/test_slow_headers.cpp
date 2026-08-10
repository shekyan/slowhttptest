// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Minimal dependency-free unit test for the slow-headers state machine. Verifies
// the byte protocol without any sockets: the initial request must look like a real
// but *unfinished* HTTP request, and followups must be well-formed header lines.
#include <cstdio>
#include <string>

#include "slowhttp/attacks/slow_headers.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::SlowHeaders;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

int main() {
  Config cfg;
  cfg.connections = 4;
  cfg.target.host = "example.test";
  cfg.target.path = "/index.html";
  cfg.max_random_data_len = 8;

  SlowHeaders attack(cfg);
  attack.on_open(0);

  Action first = attack.on_connect(0);
  check(first.kind == Action::Kind::Send, "on_connect sends bytes");
  check(static_cast<bool>(first.rearm), "on_connect arms a followup timer");

  const std::string& req = first.bytes;
  check(req.rfind("GET /index.html HTTP/1.1\r\n", 0) == 0,
        "request starts with the request line");
  check(req.find("Host: example.test\r\n") != std::string::npos,
        "request carries the Host header");
  // The whole point of Slowloris: the request must NOT be terminated.
  check(req.size() < 4 || req.compare(req.size() - 4, 4, "\r\n\r\n") != 0,
        "request is intentionally unfinished (no terminating blank line)");

  Action follow = attack.on_timer(0);
  check(follow.kind == Action::Kind::Send, "on_timer dribbles more bytes");
  check(static_cast<bool>(follow.rearm), "on_timer re-arms the timer");
  check(follow.bytes.rfind("X-", 0) == 0 &&
            follow.bytes.compare(follow.bytes.size() - 2, 2, "\r\n") == 0,
        "followup is a well-formed 'X-...: ...' header line");

  Action resp = attack.on_readable(0, "HTTP/1.1 400\r\n", 14);
  check(resp.kind == Action::Kind::Reconnect,
        "a server response triggers a reconnect");

  if (failures == 0) {
    std::printf("slow_headers: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "slow_headers: %d check(s) failed\n", failures);
  return 1;
}
