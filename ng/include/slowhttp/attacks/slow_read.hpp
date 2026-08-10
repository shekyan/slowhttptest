// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_SLOW_READ_HPP_
#define SLOWHTTP_ATTACKS_SLOW_READ_HPP_

#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// Slow read: the mirror image of Slowloris. Instead of sending a request slowly,
// send a perfectly valid, complete request for a large resource -- then refuse to
// read the response at any reasonable speed.
//
// The mechanism is TCP flow control, not HTTP. Each connection advertises a tiny
// receive window (SO_RCVBUF set before connect), so the server can only put a few
// bytes in flight. We then sip a handful of bytes every few seconds. The server's
// socket send buffer stays full, its response cannot drain, and the connection --
// plus whatever worker, memory and file descriptor it owns -- is pinned.
//
// Notably this defeats defenses aimed at Slowloris: the request is complete and
// arrives instantly, so request-header timeouts never trigger.
class SlowRead : public Attack {
 public:
  explicit SlowRead(const Config& cfg);

  const char* name() const override { return "slow read"; }

  // Randomize the advertised window per connection across [-w, -y] so the traffic
  // does not present one uniform, trivially filtered signature.
  ConnOptions conn_options(ConnId id) override;

  // Never drain: reads happen only on our own timer, in -z byte sips.
  bool wants_read_events() const override { return false; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  // Total response bytes we have deliberately left unread across all connections
  // is not observable, but what we did read is -- useful as a progress signal.
  std::uint64_t bytes_read() const { return bytes_read_; }

 private:
  std::string build_request() const;

  const Config& cfg_;
  std::string request_;  // complete, valid, and repeated -k times
  Millis read_interval_;
  std::size_t read_len_;
  std::mt19937 rng_;
  std::vector<std::uint64_t> per_conn_read_;
  std::uint64_t bytes_read_ = 0;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_SLOW_READ_HPP_
