// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_RAPID_RESET_HPP_
#define SLOWHTTP_ATTACKS_RAPID_RESET_HPP_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// HTTP/2 Rapid Reset -- CVE-2023-44487.
//
// Every other attack in this tool is slow on purpose. This one is the opposite,
// and it is here because it is the most consequential HTTP denial of service of
// the last decade and the original tool cannot express it at all.
//
// The defect is in the accounting. SETTINGS_MAX_CONCURRENT_STREAMS bounds how
// many streams may be open at once, and that bound is what a server relies on
// to size its work. A stream the client cancels with RST_STREAM stops being
// open immediately -- so it stops counting -- but the server has already
// accepted the HEADERS, decompressed them, routed the request, and often
// dispatched it to a worker. Cancel each stream the instant it is created and
// the concurrency limit never binds, while the work per second is bounded only
// by how fast frames can be pushed down one connection.
//
// The measurement that matters is therefore not "did it get slower" but "did
// the server notice". The mitigation everyone shipped is to count resets and
// close the connection once there are too many, so a server that has been fixed
// answers by hanging up -- which arrives here as a peer close and is already
// counted. A server that lets this run indefinitely has not been fixed.
//
// Rate-limited by default and by request. This is a load generator pointed at
// a known amplifier, and an unbounded default would make the tool worse than
// the thing it is testing for.
class RapidReset : public Attack {
 public:
  explicit RapidReset(const Config& cfg);

  const char* name() const override { return "HTTP/2 rapid reset"; }

  // Unlike slow read, this one must drain. The server answers before it learns
  // the stream was cancelled, and unread responses would apply TCP back
  // pressure to us -- throttling the attack with our own receive buffer.
  bool wants_read_events() const override { return true; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  long streams_reset() const { return streams_reset_; }
  long connections_recycled() const { return recycled_; }
  int per_tick() const { return per_tick_; }
  std::chrono::milliseconds tick() const { return tick_; }

 private:
  // One HEADERS immediately followed by one RST_STREAM, for `count` streams.
  std::string burst(ConnId id, int count);

  const Config& cfg_;
  std::string header_block_;  // identical for every stream, so encoded once
  std::chrono::milliseconds tick_;
  int per_tick_;
  std::vector<std::uint32_t> next_stream_;
  long streams_reset_ = 0;
  long recycled_ = 0;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_RAPID_RESET_HPP_
