// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_SLOW_TLS_HPP_
#define SLOWHTTP_ATTACKS_SLOW_TLS_HPP_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// A ClientHello that never finishes arriving.
//
// Every other mode in this tool begins after the TLS handshake has completed,
// which means every other mode is governed by an HTTP timeout. This one never
// gets that far: it opens a TCP connection to an https port and dribbles a
// single, well-formed ClientHello record, a few bytes per interval, without
// ever delivering the last of it.
//
// Whether that is a different clock from the HTTP timeouts depends on what is
// terminating TLS, and the difference is worth stating precisely because it is
// easy to overclaim. Measured against nginx 1.31:
//
//   - An http {} server has no separate handshake timeout at all. It bounds the
//     handshake with client_header_timeout, the same setting slow headers runs
//     into. With that at 10s, an unfinished ClientHello was cut at 10.0s and so
//     was an unfinished header block: one clock, no advantage.
//
//   - A stream {} server -- nginx as a TLS terminator in front of a backend --
//     has ssl_handshake_timeout, default 60s, and it is genuinely separate.
//     Against the same deployment, with client_header_timeout still 10s, an
//     unfinished ClientHello was held 60.1s while slow headers over a completed
//     handshake was cut at 10.0s.
//
// So the mode earns its place against TLS terminators, L4 load balancers and
// anything else that completes the handshake somewhere other than where the
// request timeouts live -- which is the common shape of a modern deployment,
// and the layer whose timeouts are least often revisited. Against a single
// origin serving its own TLS it may well measure the same clock twice, and the
// run will look like slow headers because it is.
//
// The record declares its full length up front and then underdelivers, so the
// server is holding a partially filled handshake buffer sized by that
// declaration. Nothing about the bytes is malformed; a server cannot
// distinguish this from a genuinely slow client, which is the same property
// that makes slow headers hard to filter.
//
// Because the handshake never completes, OpenSSL is not involved on our side at
// all -- the record is assembled by hand and written to a plain socket. That is
// also why the mode refuses an http:// target: there would be nothing on the
// other end to speak TLS.
class SlowTls : public Attack {
 public:
  explicit SlowTls(const Config& cfg);

  const char* name() const override { return "slow TLS handshake"; }

  // The server stays silent while it waits, so anything it does send is news:
  // an alert means it refused or gave up, and which one it sent says why.
  bool wants_read_events() const override { return true; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  std::string summary() const override;

  // Connections the server closed with a TLS alert rather than waiting.
  long alerted() const { return alerted_; }
  // The description code of the first alert seen, or -1 if none.
  int first_alert() const { return first_alert_; }
  std::size_t hello_size() const { return hello_.size(); }
  std::size_t declared_size() const { return declared_; }

 private:
  // The opening write: record header, handshake header, and enough of the body
  // that the server has committed to reading a ClientHello.
  std::string opening_bytes() const;
  std::string next_fragment(ConnId id);

  // The full ClientHello body the record claims to carry. The last byte is
  // never sent, so this is a bound on the run rather than a script for it.
  std::string hello_;
  std::size_t declared_ = 0;
  Millis interval_;
  std::size_t chunk_ = 0;
  // Per connection, how much of hello_ has gone out.
  std::vector<std::size_t> sent_;
  long started_ = 0;
  long alerted_ = 0;
  int first_alert_ = -1;
};

// Builds a ClientHello body (handshake message payload, without the record or
// handshake headers) for `host`, padded to exactly `target_size` bytes using
// the padding extension of RFC 7685. Exposed for testing.
std::string build_client_hello(const std::string& host, std::size_t target_size);

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_SLOW_TLS_HPP_
