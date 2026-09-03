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

// One body fragment in chunked framing: chunk-size CRLF chunk-data CRLF, size
// in lowercase hex with no extensions (RFC 9112 7.1).
//
// Free rather than a private member so the framing can be tested directly. The
// empty case is the reason: an empty fragment would encode as the terminating
// zero-length chunk and complete the request, which is the one thing this
// attack must never do. No caller can currently pass one -- but that is a
// property of today's callers, not of the framing, and it is exactly the kind
// of guarantee that quietly stops holding.
std::string chunk_frame(const std::string& body);

// Slow body, a.k.a. R-U-Dead-Yet (RUDY): send a POST whose headers are complete
// and valid -- including a large Content-Length -- then deliver the body a few
// bytes at a time. The server has been told exactly how many bytes to expect, so
// it waits for them, holding the request open.
//
// The distinction from Slowloris matters operationally: because the *headers*
// finish immediately, a request-header timeout never fires. The defense here is a
// separate request-body or total-request timeout.
//
// With --chunked the promise is dropped for framing: Transfer-Encoding: chunked
// replaces Content-Length, every body fragment goes out as its own chunk, and
// the terminating zero-length chunk is never sent. The hold is the same idea
// reached a different way, and it survives a body-size cap that is enforced
// against a declared Content-Length, because nothing is declared.
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
  // Applies chunk_frame() when --chunked is on, and returns the fragment
  // untouched otherwise, so callers stay framing-agnostic.
  std::string frame(std::string body) const;
  std::string random_token(int max_len);

  const Config& cfg_;
  // Declared before headers_: build_headers() appends it, so it has to be
  // initialized first. Member order is the initialization order.
  std::string opening_body_bytes_;  // -P payload, or the classic placeholder
  std::string headers_;      // complete headers + the opening body fragment
  std::size_t opening_body_;  // bytes of body sent up front
  Millis interval_;
  std::mt19937 rng_;
  std::vector<std::size_t> body_sent_;  // per connection, keyed by id
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_SLOW_BODY_HPP_
