// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the slow QUIC handshake state machine.
//
// The packet format itself is covered in test_quic.cpp against the RFC's own
// vectors. What matters here is the decision-making: never finishing the hello,
// and reporting what the target did rather than the first thing it said.
#include <cstdio>
#include <string>

#include "slowhttp/attacks/slow_quic.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::SlowQuic;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

static Config make_config() {
  Config cfg;
  cfg.connections = 4;
  cfg.mode = slowhttp::Mode::SlowQuic;
  cfg.target.scheme = "https";
  cfg.target.host = "example.test";
  cfg.target.port = "443";
  cfg.max_random_data_len = 32;
  return cfg;
}

// A server datagram with the given long-header packet type.
static std::string long_header(unsigned type_bits, unsigned version = 1) {
  std::string s;
  s.push_back(static_cast<char>(0xc0 | (type_bits << 4)));
  for (int i = 3; i >= 0; --i)
    s.push_back(static_cast<char>((version >> (8 * i)) & 0xff));
  s.append(40, '\0');
  return s;
}
static const unsigned kInitial = 0, kHandshake = 2, kRetry = 3;

static void test_every_packet_is_a_legal_datagram() {
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  a.on_open(0);
  Action c = a.on_connect(0);
  check(c.kind == Action::Kind::Send, "the handshake opens with a packet");
  check(c.bytes.size() == 1200,
        "which is 1200 bytes, the floor RFC 9000 14.1 sets for an Initial");
  Action t = a.on_timer(0);
  check(t.kind == Action::Kind::Send, "the dribble continues on the timer");
  check(t.bytes.size() == 1200,
        "and a 32-byte fragment still costs a whole datagram");
}

static void test_partial_never_delivers_the_whole_hello() {
  // The defining property of the mode. However long the run lasts, the server
  // must never be able to assemble a parseable ClientHello -- if it could, this
  // would stop being a handshake that is held and become one that completes,
  // and the run would measure an ordinary connection instead.
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  a.on_open(0);
  const std::size_t hello = a.hello_size();
  check(hello > 32, "the hello is longer than one fragment, or nothing is held");

  a.on_connect(0);
  check(a.delivered(0) <= hello - 1, "the opening packet withholds something");
  for (int i = 0; i < 500; ++i) {
    a.on_timer(0);
    if (a.delivered(0) > hello - 1) break;
  }
  check(a.delivered(0) <= hello - 1,
        "after 500 intervals the hello is still short of complete");
  check(a.delivered(0) == hello - 1,
        "and it has been dribbled right up to that last withheld byte");
  // It must also keep sending once the fragments run out, or the server's idle
  // timer reaps the connection and the hold ends on its own.
  Action t = a.on_timer(0);
  check(t.kind == Action::Kind::Send,
        "the last fragment is retransmitted to keep the connection alive");
}

static void test_complete_sends_once_and_goes_silent() {
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Complete);
  a.on_open(0);
  Action c = a.on_connect(0);
  check(c.kind == Action::Kind::Send, "the whole hello goes out at once");
  const long long after_connect = a.bytes_out();
  for (int i = 0; i < 5; ++i) {
    Action t = a.on_timer(0);
    check(t.kind != Action::Kind::Send,
          "and then nothing more is ever sent: the wait is the measurement");
  }
  check(a.bytes_out() == after_connect, "so the byte count stops growing");
}

static void test_handshake_outranks_an_earlier_initial() {
  // A server ACKs in an Initial before its Handshake flight arrives. Counting
  // the first reply would file a completed key exchange under "merely held".
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Complete);
  a.on_open(0);
  a.on_connect(0);

  const std::string ack = long_header(kInitial);
  a.on_readable(0, ack.data(), ack.size());
  check(a.held() == 1 && a.handshaked() == 0, "the ACK alone reads as held");

  const std::string hs = long_header(kHandshake);
  a.on_readable(0, hs.data(), hs.size());
  check(a.handshaked() == 1, "the Handshake flight is recorded");
  check(a.held() == 0,
        "and the connection is no longer counted as merely held -- one"
        " connection must not appear in two buckets");
}

static void test_a_weaker_reply_does_not_undo_a_stronger_one() {
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Complete);
  a.on_open(0);
  a.on_connect(0);
  const std::string hs = long_header(kHandshake);
  a.on_readable(0, hs.data(), hs.size());
  const std::string ack = long_header(kInitial);
  a.on_readable(0, ack.data(), ack.size());  // a retransmitted ACK arrives late
  check(a.handshaked() == 1 && a.held() == 0,
        "a later ACK does not demote a handshake that already happened");
}

static void test_retry_frees_the_slot() {
  // A Retry means the server created no state at all. Holding a slot against a
  // connection that does not exist would overstate what the run achieved.
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  a.on_open(0);
  a.on_connect(0);
  const std::string retry = long_header(kRetry);
  Action r = a.on_readable(0, retry.data(), retry.size());
  check(r.kind == Action::Kind::Reconnect, "a Retry recycles the connection");
  check(a.retried() == 1, "and is counted as address validation");
  check(a.handshaked() == 0 && a.held() == 0, "with nothing held");
}

static void test_version_negotiation_is_not_a_hold() {
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  a.on_open(0);
  a.on_connect(0);
  const std::string vn = long_header(kInitial, /*version=*/0);
  a.on_readable(0, vn.data(), vn.size());
  check(a.held() == 0 && a.handshaked() == 0 && a.retried() == 0,
        "a version negotiation means the target refused the version, not that"
        " it is holding anything");
}

static void test_connections_get_distinct_identities() {
  // Two connections sharing a connection ID would be one connection to the
  // server, and the run would report holding N while holding one.
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  a.on_open(0);
  a.on_open(1);
  const std::string p0 = a.on_connect(0).bytes;
  const std::string p1 = a.on_connect(1).bytes;
  // The DCID sits at a fixed offset: 1 flags + 4 version + 1 length.
  check(p0.compare(6, 8, p1, 6, 8) != 0,
        "each connection carries its own destination connection ID");
}

static void test_summary_says_nothing_without_a_connection() {
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  check(a.summary().empty(), "a run that reached nothing describes nothing");
}

int main() {
  if (!slowhttp::quic::available()) {
    std::printf("slow_quic: skipped, this build has no crypto backend\n");
    return 0;
  }
  test_every_packet_is_a_legal_datagram();
  test_partial_never_delivers_the_whole_hello();
  test_complete_sends_once_and_goes_silent();
  test_handshake_outranks_an_earlier_initial();
  test_a_weaker_reply_does_not_undo_a_stronger_one();
  test_retry_frees_the_slot();
  test_version_negotiation_is_not_a_hold();
  test_connections_get_distinct_identities();
  test_summary_says_nothing_without_a_connection();
  if (failures == 0) {
    std::printf("slow_quic: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "slow_quic: %d check(s) failed\n", failures);
  return 1;
}
