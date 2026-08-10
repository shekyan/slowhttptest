// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the slow-read state machine. The defining property, and the one
// most worth guarding against regression, is that its request is COMPLETE -- the
// exact opposite of slow headers. That is what makes it slip past request-header
// timeouts, so a change that broke it would quietly gut the attack.
#include <cstdio>
#include <set>
#include <string>

#include "slowhttp/attacks/slow_read.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::SlowRead;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

static Config make_config() {
  Config cfg;
  cfg.connections = 4;
  cfg.mode = slowhttp::Mode::SlowRead;
  cfg.target.host = "example.test";
  cfg.target.path = "/big";
  cfg.read_len = 5;
  cfg.read_interval = std::chrono::seconds(3);
  cfg.window_lower = 1;
  cfg.window_upper = 8;
  return cfg;
}

static void test_request_shape() {
  Config cfg = make_config();
  SlowRead attack(cfg);
  attack.on_open(0);

  Action a = attack.on_connect(0);
  check(a.kind == Action::Kind::Send, "on_connect sends the request");
  check(static_cast<bool>(a.rearm), "on_connect arms the read timer");

  const std::string& req = a.bytes;
  check(req.rfind("GET /big HTTP/1.1\r\n", 0) == 0, "request line is well formed");
  check(req.find("Host: example.test\r\n") != std::string::npos, "Host header present");
  // The whole point: unlike Slowloris this request is finished and valid.
  check(req.size() >= 4 && req.compare(req.size() - 4, 4, "\r\n\r\n") == 0,
        "request is COMPLETE (terminated) -- defeats header timeouts");
  check(req.find("Accept-Encoding: identity") != std::string::npos,
        "asks for an uncompressed body so the response stays large");
}

static void test_read_behavior() {
  Config cfg = make_config();
  SlowRead attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  check(!attack.wants_read_events(),
        "slow read opts out of readability events (must not drain)");

  Action t = attack.on_timer(0);
  check(t.kind == Action::Kind::Read, "timer produces a bounded read");
  check(t.read_bytes == 5, "reads exactly -z bytes per tick");
  check(t.rearm && t.rearm->count() == 3000, "re-arms at the -n interval");

  Action r = attack.on_readable(0, "AAAAA", 5);
  check(r.kind == Action::Kind::Idle, "consuming bytes schedules nothing extra");
  check(attack.bytes_read() == 5, "counts the bytes actually sipped");
}

static void test_window_range() {
  Config cfg = make_config();
  cfg.window_lower = 4;
  cfg.window_upper = 6;
  SlowRead attack(cfg);

  std::set<int> seen;
  for (int i = 0; i < 200; ++i) {
    int w = attack.conn_options(i % cfg.connections).recv_buffer;
    check(w >= 4 && w <= 6, "advertised window stays inside [-w, -y]");
    seen.insert(w);
  }
  check(seen.size() > 1, "window is randomized across connections, not constant");
}

static void test_single_value_window() {
  // Degenerate but legal range: -w == -y must not trip the distribution.
  Config cfg = make_config();
  cfg.window_lower = cfg.window_upper = 7;
  SlowRead attack(cfg);
  check(attack.conn_options(0).recv_buffer == 7, "collapsed window range works");
}

static void test_pipelining() {
  Config cfg = make_config();
  cfg.pipeline_factor = 3;
  SlowRead attack(cfg);
  const std::string req = attack.on_connect(0).bytes;

  std::size_t count = 0;
  for (std::size_t p = req.find("GET /big"); p != std::string::npos;
       p = req.find("GET /big", p + 1)) {
    ++count;
  }
  check(count == 3, "-k stacks the request that many times");
  check(req.find("Connection: keep-alive") != std::string::npos,
        "keep-alive so a pipelined burst is answered on one connection");
}

int main() {
  test_request_shape();
  test_read_behavior();
  test_window_range();
  test_single_value_window();
  test_pipelining();
  if (failures == 0) {
    std::printf("slow_read: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "slow_read: %d check(s) failed\n", failures);
  return 1;
}
