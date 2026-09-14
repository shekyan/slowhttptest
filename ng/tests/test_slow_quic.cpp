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

static void test_sni_is_omitted_for_a_literal_address() {
  // RFC 6066 3 forbids a literal address in SNI, and a server enforcing that
  // rejects the hello outright -- which would measure the rejection instead of
  // a hold. The hosts here are the same length, so the only thing that can
  // make one hello shorter is the missing extension.
  Config named = make_config();
  named.target.host = "example.tes";  // 11 characters
  Config literal = make_config();
  literal.target.host = "203.0.113.5";  // also 11
  Config v6 = make_config();
  v6.target.host = "2001:db8::1";

  SlowQuic a(named, SlowQuic::Hello::Partial);
  SlowQuic b(literal, SlowQuic::Hello::Partial);
  SlowQuic c(v6, SlowQuic::Hello::Partial);
  check(b.hello_size() < a.hello_size(),
        "an IPv4 literal target carries no SNI");
  check(c.hello_size() < a.hello_size(),
        "nor does an IPv6 literal");
  check(b.hello_size() == c.hello_size(),
        "and both literals produce the same hello");
}

static void test_a_retry_can_be_superseded_by_a_handshake() {
  // A server may Retry one packet and, once re-addressed, go on to answer a
  // later one. The connection has to leave the Retry bucket when that happens
  // or the run reports address validation that did not hold.
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Complete);
  a.on_open(0);
  a.on_connect(0);
  const std::string retry = long_header(kRetry);
  a.on_readable(0, retry.data(), retry.size());
  check(a.retried() == 1, "the Retry is counted first");
  const std::string hs = long_header(kHandshake);
  a.on_readable(0, hs.data(), hs.size());
  check(a.handshaked() == 1 && a.retried() == 0,
        "and is given up when the same connection gets a flight");
}

static void test_summary_names_what_the_target_did() {
  // Each verdict has to be distinguishable, because each means something
  // different about the target's defenses. Asserting the distinguishing words
  // rather than the whole sentence keeps this from breaking on wording.
  {
    Config cfg = make_config();
    SlowQuic a(cfg, SlowQuic::Hello::Partial);
    a.on_open(0);
    a.on_connect(0);
    const std::string retry = long_header(kRetry);
    a.on_readable(0, retry.data(), retry.size());
    check(a.summary().find("Retry") != std::string::npos,
          "a validated target is reported as validating");
  }
  {
    Config cfg = make_config();
    SlowQuic a(cfg, SlowQuic::Hello::Complete);
    a.on_open(0);
    a.on_connect(0);
    const std::string ack = long_header(kInitial);
    a.on_readable(0, ack.data(), ack.size());
    const std::string s = a.summary();
    check(s.find("held") != std::string::npos, "a held target is reported as held");
    check(s.find("cannot parse") == std::string::npos,
          "and the complete mode does not claim an unparseable hello");
  }
  {
    Config cfg = make_config();
    SlowQuic a(cfg, SlowQuic::Hello::Partial);
    a.on_open(0);
    a.on_connect(0);
    const std::string ack = long_header(kInitial);
    a.on_readable(0, ack.data(), ack.size());
    check(a.summary().find("cannot parse") != std::string::npos,
          "the partial mode says why the target is stuck");
  }
  {
    Config cfg = make_config();
    SlowQuic a(cfg, SlowQuic::Hello::Partial);
    a.on_open(0);
    a.on_connect(0);
    check(a.summary().find("never answered") != std::string::npos,
          "silence is reported as silence, not as a hold");
  }
}

static void test_amplification_above_the_rfc_limit_is_flagged() {
  // RFC 9000 8.1 caps what a server may send to an unvalidated address at
  // three times what it received, and this mode never validates. Measured 3.4x
  // against quic-go, so the threshold is not hypothetical.
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Complete);
  a.on_open(0);
  a.on_connect(0);  // one 1200-byte datagram out
  const std::string hs = long_header(kHandshake);
  a.on_readable(0, hs.data(), hs.size());
  const std::string modest = a.summary();
  check(modest.find("above the 3x") == std::string::npos,
        "a small reply is not flagged");

  const std::string big(2000, '\0');
  a.on_readable(0, big.data(), big.size());
  a.on_readable(0, big.data(), big.size());  // now past 3x of 1200
  const std::string loud = a.summary();
  check(a.bytes_in() > 3 * a.bytes_out(), "the run really is past the limit");
  check(loud.find("above the 3x") != std::string::npos,
        "and crossing it is called out");
}

static void test_out_of_range_ids_are_refused_not_indexed() {
  // These guards are the difference between a bug elsewhere in the engine and
  // an out-of-bounds write into the per-connection vector. Nothing should ever
  // pass an id outside the configured range, which is exactly why the guards
  // have to be checked here rather than trusted.
  Config cfg = make_config();  // 4 connections
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  for (slowhttp::ConnId bad : {static_cast<slowhttp::ConnId>(-1),
                               static_cast<slowhttp::ConnId>(4),
                               static_cast<slowhttp::ConnId>(9999)}) {
    a.on_open(bad);
    check(a.on_connect(bad).kind != Action::Kind::Send,
          "an out-of-range id sends nothing");
    check(a.on_timer(bad).kind != Action::Kind::Send,
          "and is not dribbled to");
    const std::string ack = long_header(kInitial);
    check(a.on_readable(bad, ack.data(), ack.size()).kind == Action::Kind::Idle,
          "and its replies are dropped rather than counted");
    check(a.delivered(bad) == 0, "with no state to read back");
  }
  check(a.held() == 0 && a.handshaked() == 0 && a.retried() == 0,
        "nothing out of range reaches the tally");
}

static void test_status_note_reports_replies_not_sockets() {
  // The engine's socket count cannot mean anything over UDP: connect() on a
  // datagram socket returns without putting a packet on the wire, so it reads
  // the same against a live server and against a black hole. This row is what
  // carries the real number, so it has to move when the target answers.
  Config cfg = make_config();
  SlowQuic a(cfg, SlowQuic::Hello::Partial);
  check(a.status_note().empty(), "nothing to say before anything is opened");

  a.on_open(0);
  a.on_connect(0);
  const std::string opened = a.status_note();
  check(opened.find("of 1 opened") != std::string::npos,
        "an opened socket is counted as opened");
  check(opened.find("0 held") != std::string::npos,
        "but not as held, because the target has said nothing");

  const std::string ack = long_header(kInitial);
  a.on_readable(0, ack.data(), ack.size());
  check(a.status_note().find("1 held") != std::string::npos,
        "and becomes held only once the target replies");
}

static void test_all_retry_qualifies_a_denial_verdict() {
  // The probe and the attack measure different things, and when they disagree
  // the disagreement is the finding. If every connection was answered with a
  // Retry the target created no handshake state, so a probe failure cannot be
  // this attack exhausting it -- and the verdict has to say so, or the tool
  // takes credit for an outage it did not cause.
  Config cfg = make_config();
  {
    SlowQuic a(cfg, SlowQuic::Hello::Partial);
    a.on_open(0);
    a.on_connect(0);
    const std::string retry = long_header(kRetry);
    a.on_readable(0, retry.data(), retry.size());
    const std::string c = a.verdict_caveat();
    check(!c.empty(), "an all-Retry run qualifies the verdict");
    check(c.find("shed") != std::string::npos,
          "and names source-address shedding as the likelier reading");
  }
  {  // A target that actually held something gets no such excuse.
    SlowQuic a(cfg, SlowQuic::Hello::Partial);
    a.on_open(0);
    a.on_connect(0);
    const std::string ack = long_header(kInitial);
    a.on_readable(0, ack.data(), ack.size());
    check(a.verdict_caveat().empty(),
          "a run that held connections is not explained away");
  }
  {  // Nor does a run that got a flight.
    SlowQuic a(cfg, SlowQuic::Hello::Complete);
    a.on_open(0);
    a.on_connect(0);
    const std::string hs = long_header(kHandshake);
    a.on_readable(0, hs.data(), hs.size());
    check(a.verdict_caveat().empty(),
          "nor is one where the target did the expensive work");
  }
  {  // The case the guard exists for: a target that Retries some connections
     // and accepts others did take on work, so the denial is not explained
     // away just because a Retry appeared somewhere in the run.
    SlowQuic a(cfg, SlowQuic::Hello::Partial);
    a.on_open(0);
    a.on_connect(0);
    const std::string retry = long_header(kRetry);
    a.on_readable(0, retry.data(), retry.size());
    a.on_open(1);
    a.on_connect(1);
    const std::string ack = long_header(kInitial);
    a.on_readable(1, ack.data(), ack.size());
    check(a.retried() == 1 && a.held() == 1, "the run really is mixed");
    check(a.verdict_caveat().empty(),
          "a mixed run is not explained away by the Retries in it");
  }
  {  // The same mix, but with a flight rather than a hold: a target that
     // signed for even one handshake spent real work, whatever it Retried.
    SlowQuic a(cfg, SlowQuic::Hello::Complete);
    a.on_open(0);
    a.on_connect(0);
    const std::string retry = long_header(kRetry);
    a.on_readable(0, retry.data(), retry.size());
    a.on_open(1);
    a.on_connect(1);
    const std::string hs = long_header(kHandshake);
    a.on_readable(1, hs.data(), hs.size());
    check(a.retried() == 1 && a.handshaked() == 1, "the run really is mixed");
    check(a.verdict_caveat().empty(),
          "Retries alongside a completed flight do not excuse the denial");
  }
  {  // And nothing is claimed before the run starts.
    SlowQuic a(cfg, SlowQuic::Hello::Partial);
    check(a.verdict_caveat().empty(), "silence before anything is attempted");
  }
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
  test_sni_is_omitted_for_a_literal_address();
  test_a_retry_can_be_superseded_by_a_handshake();
  test_summary_names_what_the_target_did();
  test_amplification_above_the_rfc_limit_is_flagged();
  test_out_of_range_ids_are_refused_not_indexed();
  test_status_note_reports_replies_not_sockets();
  test_all_retry_qualifies_a_denial_verdict();
  test_summary_says_nothing_without_a_connection();
  if (failures == 0) {
    std::printf("slow_quic: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "slow_quic: %d check(s) failed\n", failures);
  return 1;
}
