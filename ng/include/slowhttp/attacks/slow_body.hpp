// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_SLOW_BODY_HPP_
#define SLOWHTTP_ATTACKS_SLOW_BODY_HPP_

#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// Slow body, a.k.a. R-U-Dead-Yet (RUDY): send a POST whose headers are complete
// and valid -- including a large Content-Length -- then deliver the body a few
// bytes at a time. The server has been told exactly how many bytes to expect, so
// it waits for them, holding the request open.
//
// The distinction from Slowloris matters operationally: because the *headers*
// finish immediately, a request-header timeout never fires. The defense here is a
// separate request-body or total-request timeout.
class SlowBody : public Attack {
 public:
  explicit SlowBody(const Config& cfg);

  const char* name() const override { return "slow body (R-U-Dead-Yet)"; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

 private:
  std::string build_headers() const;
  std::string followup_chunk();
  std::string random_token(int max_len);

  const Config& cfg_;
  std::string headers_;      // complete headers + the opening body fragment
  std::size_t opening_body_;  // bytes of body sent up front
  Millis interval_;
  std::mt19937 rng_;
  std::vector<std::size_t> body_sent_;  // per connection, keyed by id
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_SLOW_BODY_HPP_
