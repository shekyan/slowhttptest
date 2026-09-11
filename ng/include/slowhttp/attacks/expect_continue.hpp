// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_EXPECT_CONTINUE_HPP_
#define SLOWHTTP_ATTACKS_EXPECT_CONTINUE_HPP_

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// Expect: 100-continue, and then no body.
//
// The request is complete and correct: headers terminated, a Content-Length
// announced, and Expect: 100-continue asking the server whether it wants the
// body. RFC 9110 10.1.1 then makes the client wait for an interim response
// before sending anything more -- so a client that simply waits is not
// misbehaving, it is doing exactly what the header is for.
//
// What that tests is a timeout most stacks keep separately from the one slow
// body exercises. Slow body makes the server read a body that arrives too
// slowly; this makes it commit to receiving a body that never begins. A server
// that answers "100 Continue" has said it is ready and usually has a request
// object, a buffer and often a worker already attached to that connection. The
// question is how long it holds them when nothing follows, and the answer is
// frequently governed by a different setting -- or by none at all.
//
// The second measurement is whether the interim response arrives at all.
// Sending it is optional (RFC 9110 10.1.1 lets a server skip straight to the
// final status), and proxies in front of an origin differ on whether they
// answer it themselves, forward it, or swallow it. That difference is worth
// seeing on its own, so it is counted and reported rather than assumed.
class ExpectContinue : public Attack {
 public:
  explicit ExpectContinue(const Config& cfg);

  const char* name() const override { return "expect 100-continue"; }

  // Unlike the other withholding attacks, this one has to read: whether the
  // server sent the interim response is half of what the run measures, and it
  // only exists on the wire.
  bool wants_read_events() const override { return true; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  std::string summary() const override;

  // Connections the server invited to send a body.
  long continued() const { return continued_; }
  // Connections answered with a final status instead -- the server declined to
  // wait, which is the healthy response.
  long answered() const { return answered_; }
  std::size_t request_size() const { return request_.size(); }

 private:
  std::string build_request() const;
  // Classifies one complete status line. Returns true if the connection is
  // finished with us.
  bool consume(ConnId id, std::string& line);

  const Config& cfg_;
  std::string request_;
  Millis interval_;
  // Per connection, the reply bytes seen so far. Bounded: a peer that never
  // sends a newline must not be able to grow this without limit.
  std::vector<std::string> reply_;
  std::vector<bool> got_continue_;
  long continued_ = 0;
  long answered_ = 0;
  // Connections that actually carried the request. Without this the summary
  // described a target that was never reached as one holding our request.
  long started_ = 0;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_EXPECT_CONTINUE_HPP_
