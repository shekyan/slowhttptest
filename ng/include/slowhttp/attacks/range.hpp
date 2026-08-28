// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_RANGE_HPP_
#define SLOWHTTP_ATTACKS_RANGE_HPP_

#include <cstdint>
#include <string>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// Range attack, a.k.a. "Apache killer" (CVE-2011-3192).
//
// Unlike the other three modes this one is not slow at all: it sends a single
// complete request, immediately. The leverage is amplification, not connection
// holding. A few kilobytes of Range header naming thousands of overlapping byte
// ranges once drove affected servers to buffer (and gzip) a separate copy of the
// resource per range, turning a trivial request into hundreds of megabytes of
// server-side memory and CPU.
//
// The bug itself has been patched since 2011, so against a current server this is
// a regression check rather than a live exploit -- which is exactly why it is
// worth keeping: it answers "is this thing still vulnerable?".
class RangeAttack : public Attack {
 public:
  explicit RangeAttack(const Config& cfg);

  const char* name() const override { return "range (Apache killer)"; }

  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  // Number of range specs in a single request, for reporting.
  int range_count() const { return range_count_; }
  std::size_t request_size() const { return request_.size(); }

 private:
  std::string build_request();

  const Config& cfg_;
  std::string request_;
  int range_count_ = 0;
};

// Builds the classic overlapping-range header, matching the original generator:
//   Range: bytes=0-,<start>-0,<start>-1,...,<start>-<limit>
// Returns the number of range specs produced.
int build_range_header(int start, int limit, std::string* out);

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_RANGE_HPP_
