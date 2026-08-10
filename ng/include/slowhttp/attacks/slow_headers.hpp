// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_SLOW_HEADERS_HPP_
#define SLOWHTTP_ATTACKS_SLOW_HEADERS_HPP_

#include <random>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// Slow headers, a.k.a. Slowloris: open a connection, send a valid-looking but
// deliberately unfinished request (never the terminating CRLF CRLF), then dribble
// one extra header line every `interval` to keep the connection alive and hold a
// worker/thread on the server hostage.
class SlowHeaders : public Attack {
 public:
  explicit SlowHeaders(const Config& cfg);

  const char* name() const override { return "slow headers (Slowloris)"; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

 private:
  std::string initial_request() const;
  std::string followup_line();
  std::string random_token(int max_len);

  const Config& cfg_;
  Millis interval_;
  std::mt19937 rng_;
  std::vector<int> followups_sent_;  // per-connection counter, keyed by id
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_SLOW_HEADERS_HPP_
