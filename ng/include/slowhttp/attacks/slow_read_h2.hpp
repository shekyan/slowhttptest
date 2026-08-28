// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_SLOW_READ_H2_HPP_
#define SLOWHTTP_ATTACKS_SLOW_READ_H2_HPP_

#include <chrono>
#include <cstddef>
#include <random>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// Slow read over HTTP/2 -- internal data buffering, CVE-2019-9517.
//
// The HTTP/1.1 version of this attack starves one thing: the TCP receive
// window, by asking for a tiny SO_RCVBUF and then not reading. A server sized
// for it keeps the undelivered response in kernel socket buffers, which are
// cheap and capped.
//
// HTTP/2 adds a second, independent window at the application layer, and the
// two can be set against each other. This tells the server, via SETTINGS and
// WINDOW_UPDATE, that it may send as much as the protocol allows -- so the
// server generates the response and holds it in its *own* buffers -- while the
// TCP window underneath stays as small as the kernel will allow, so none of it
// can actually leave. Application memory is far more expensive than socket
// buffers, and unlike the 1.1 case it is not bounded by anything the operator
// configured.
//
// It also sidesteps the standard Slowloris mitigation. Per-IP connection limits
// count connections; this pins many streams inside one, so the connection count
// stays unremarkable while the work queued behind it does not.
//
// Nothing here reads a frame. The attack never needs to know what the server
// said, only that it was asked for a great deal and cannot deliver it, so the
// class sends and then goes quiet -- which is also why no HPACK decoder or
// frame parser exists in this tool.
class SlowReadH2 : public Attack {
 public:
  explicit SlowReadH2(const Config& cfg);

  const char* name() const override { return "slow read (HTTP/2)"; }

  // Same starvation as the HTTP/1.1 attack: a deliberately small receive
  // buffer, applied before connect so it is what gets advertised.
  ConnOptions conn_options(ConnId id) override;

  // Slow read exists to not read. Being woken per arriving byte and draining is
  // the opposite of the attack.
  bool wants_read_events() const override { return false; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  // Bytes the client has accepted, across every connection.
  long bytes_read() const { return bytes_read_; }
  // The opening burst, for reporting and for tests.
  std::size_t handshake_size() const { return handshake_.size(); }
  int streams_per_connection() const { return streams_; }

 private:
  std::string build_handshake() const;
  void append_request(std::string& out, std::uint32_t stream_id) const;

  const Config& cfg_;
  int streams_;
  std::string handshake_;
  std::chrono::milliseconds read_interval_;
  std::size_t read_len_;
  std::mt19937 rng_;
  std::vector<long> per_conn_read_;
  long bytes_read_ = 0;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_SLOW_READ_H2_HPP_
