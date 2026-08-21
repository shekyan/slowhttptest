// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_CONTINUATION_HPP_
#define SLOWHTTP_ATTACKS_CONTINUATION_HPP_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// HTTP/2 CONTINUATION flood.
//
// The direct analogue of slow headers, and the reason it is worth having is
// that HTTP/2 made the same idea cost the server more while making it harder to
// see.
//
// A header block may be split across a HEADERS frame and any number of
// CONTINUATION frames, and it is only complete when one of them carries
// END_HEADERS. Until then the server cannot act on it: HPACK is a stateful
// compression context, so a partial block cannot be decoded, dispatched or
// discarded without desynchronising every later block on that connection. It
// has to be kept. RFC 7540 also forbids interleaving anything else between the
// HEADERS and its final CONTINUATION, on any stream, so the connection is
// committed to this one block until the client finishes it -- which this attack
// never does.
//
// Two things make it worse than its HTTP/1.1 ancestor. The cost is memory that
// grows for as long as the client keeps sending, rather than one pinned
// connection slot. And in many stacks it happens entirely before the point
// where a request is logged, so a server can be driven to exhaustion with
// nothing whatsoever in its access log -- the operator sees memory climb and no
// requests to explain it.
//
// -i and -x mean here what they mean for slow headers: how often another
// fragment goes out, and how large the random field inside it is.
class ContinuationFlood : public Attack {
 public:
  explicit ContinuationFlood(const Config& cfg);

  const char* name() const override { return "HTTP/2 CONTINUATION flood"; }

  // Nothing is expected back. The server cannot answer a request whose headers
  // have not finished arriving, which is the whole point.
  bool wants_read_events() const override { return false; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  long fragments_sent() const { return fragments_; }
  std::size_t opening_size() const { return opening_.size(); }

 private:
  std::string opening() const;
  std::string fragment();
  std::string random_token(int max_len);

  const Config& cfg_;
  std::string opening_;
  std::chrono::milliseconds interval_;
  std::mt19937 rng_;
  long fragments_ = 0;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_CONTINUATION_HPP_
