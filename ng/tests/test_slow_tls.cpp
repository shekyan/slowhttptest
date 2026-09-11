// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the slow TLS handshake.
//
// The hello is assembled by hand, so the tests check it against the wire format
// rather than against the code that produced it: a length field that disagrees
// with the bytes it counts would be rejected by the server as a decode error,
// and the run would measure that rejection instead of a hold.
#include <cstdint>
#include <cstdio>
#include <string>

#include "slowhttp/attacks/slow_tls.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::SlowTls;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

static unsigned be16(const std::string& s, std::size_t at) {
  return (static_cast<unsigned char>(s[at]) << 8) |
         static_cast<unsigned char>(s[at + 1]);
}
static unsigned be24(const std::string& s, std::size_t at) {
  return (static_cast<unsigned char>(s[at]) << 16) |
         (static_cast<unsigned char>(s[at + 1]) << 8) |
         static_cast<unsigned char>(s[at + 2]);
}

static Config make_config() {
  Config cfg;
  cfg.connections = 4;
  cfg.mode = slowhttp::Mode::SlowTls;
  cfg.target.scheme = "https";
  cfg.target.host = "example.test";
  cfg.target.port = "443";
  cfg.target.path = "/";
  cfg.max_random_data_len = 8;
  return cfg;
}

// Walks the extension block, checking every length field closes exactly on the
// block's end. A server parses this the same way, and stops at the first
// disagreement.
static bool extensions_well_formed(const std::string& hello, std::size_t at,
                                   bool* saw_sni, bool* saw_padding) {
  if (at + 2 > hello.size()) return false;
  const std::size_t total = be16(hello, at);
  at += 2;
  if (at + total != hello.size()) return false;
  const std::size_t end = at + total;
  while (at < end) {
    if (at + 4 > end) return false;
    const unsigned type = be16(hello, at);
    const std::size_t len = be16(hello, at + 2);
    at += 4;
    if (at + len > end) return false;
    if (type == 0x0000) *saw_sni = true;
    if (type == 0x0015) *saw_padding = true;
    at += len;
  }
  return at == end;
}

// Parses far enough to reach the extensions, returning their offset.
static std::size_t walk_to_extensions(const std::string& h) {
  std::size_t at = 2 + 32;              // legacy_version, random
  at += 1 + static_cast<unsigned char>(h[at]);   // legacy_session_id
  at += 2 + be16(h, at);                // cipher_suites
  at += 1 + static_cast<unsigned char>(h[at]);   // compression_methods
  return at;
}

static void test_hello_is_well_formed() {
  const std::string h = slowhttp::build_client_hello("example.test", 16380);
  check(h.size() == 16380, "the hello is exactly the requested size");
  check(be16(h, 0) == 0x0303, "legacy_version is TLS 1.2, as RFC 8446 requires");
  check(static_cast<unsigned char>(h[2 + 32]) == 32,
        "a 32-byte legacy_session_id, the middlebox-compatibility shape");

  bool sni = false, padding = false;
  check(extensions_well_formed(h, walk_to_extensions(h), &sni, &padding),
        "every extension length closes exactly on the end of the block");
  check(sni, "server_name is present, so name-based routing reaches the target");
  check(padding, "padding carries the hello up to the requested size");
}

static void test_padding_is_what_grows_it() {
  const std::string small = slowhttp::build_client_hello("example.test", 0);
  const std::string big = slowhttp::build_client_hello("example.test", 16380);
  check(small.size() < 400, "unpadded, the hello is the size a client sends");
  check(big.size() == 16380, "padded, it is whatever was asked for");
  bool sni = false, pad = false;
  check(extensions_well_formed(small, walk_to_extensions(small), &sni, &pad),
        "the unpadded hello is well formed too");
  check(!pad, "and carries no padding extension at all");
}

// Drains everything a connection will ever send, so a check can look at the
// whole hello rather than the first few bytes of it. Searching only the opening
// write would pass no matter what the hello contained.
static std::string drain(SlowTls& attack) {
  std::string all = attack.on_connect(0).bytes;
  for (;;) {
    Action t = attack.on_timer(0);
    if (t.kind != Action::Kind::Send || t.bytes.empty()) break;
    all += t.bytes;
  }
  return all;
}

static void test_no_sni_for_a_literal_address() {
  // RFC 6066 3: a literal address is not a legal SNI host name. Sending one
  // invites a rejection, which would measure the rejection and not the hold.
  Config v4 = make_config();
  v4.target.host = "192.0.2.1";
  v4.max_random_data_len = 4096;
  SlowTls a4(v4);
  a4.on_open(0);
  check(drain(a4).find("192.0.2.1") == std::string::npos,
        "a literal IPv4 address is not offered as SNI");

  Config v6 = make_config();
  v6.target.host = "2001:db8::1";
  v6.max_random_data_len = 4096;
  SlowTls a6(v6);
  a6.on_open(0);
  check(drain(a6).find("2001:db8") == std::string::npos,
        "nor is an IPv6 literal");

  Config named = make_config();
  named.max_random_data_len = 4096;
  SlowTls an(named);
  an.on_open(0);
  check(drain(an).find("example.test") != std::string::npos,
        "but a real host name is, so name-based routing reaches the target");
}

static void test_opening_write_declares_the_whole_record() {
  Config cfg = make_config();
  SlowTls attack(cfg);
  Action a = attack.on_connect(0);
  check(a.kind == Action::Kind::Send, "the connection opens by sending");
  const std::string& b = a.bytes;
  check(static_cast<unsigned char>(b[0]) == 0x16, "a handshake record");
  check(be16(b, 1) == 0x0301, "with the legacy record version every client uses");
  const std::size_t record_len = be16(b, 3);
  check(record_len <= 16384,
        "within the record ceiling; more is record_overflow, an instant reject");
  // This number is the whole mechanism: it is what the server sizes its
  // handshake buffer from and what it then waits to fill. Declaring less than
  // the hello would let the record complete early and the handshake proceed;
  // declaring more than the bytes that exist is a decode error once they land.
  check(record_len == attack.declared_size() + 4,
        "the record declares exactly the ClientHello it will never finish");
  check(static_cast<unsigned char>(b[5]) == 0x01, "carrying a ClientHello");
  check(be24(b, 6) == attack.declared_size(),
        "whose declared length is the whole hello");
  // The declaration is the point: the server sizes its buffer from it and then
  // waits for bytes that do not come.
  check(b.size() < record_len,
        "and the opening write delivers only a fraction of what it declared");
}

static void test_the_last_byte_is_never_sent() {
  Config cfg = make_config();
  cfg.max_random_data_len = 4096;  // drain it fast
  SlowTls attack(cfg);
  attack.on_open(0);
  std::size_t sent = attack.on_connect(0).bytes.size() - 9;  // minus headers
  for (int i = 0; i < 100; ++i) {
    Action t = attack.on_timer(0);
    sent += t.bytes.size();
    check(static_cast<bool>(t.rearm), "the timer always re-arms");
  }
  check(sent == attack.declared_size() - 1,
        "the hello stops one byte short, forever");
  check(attack.on_timer(0).kind != Action::Kind::Send,
        "and once drained the timer sends nothing more");
  check(attack.on_timer(0).kind != Action::Kind::Close,
        "but it does not hang up either -- holding open is the measurement");
}

static void test_each_connection_dribbles_independently() {
  Config cfg = make_config();
  SlowTls attack(cfg);
  attack.on_open(0);
  attack.on_open(1);
  attack.on_connect(0);
  attack.on_connect(1);
  const std::string a = attack.on_timer(0).bytes;
  const std::string b = attack.on_timer(1).bytes;
  check(!a.empty() && a == b,
        "two connections at the same offset send the same bytes, not halves "
        "of one stream");
}

static void test_reused_slot_restarts_the_hello() {
  Config cfg = make_config();
  cfg.max_random_data_len = 4096;
  SlowTls attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);
  for (int i = 0; i < 10; ++i) attack.on_timer(0);
  attack.on_open(0);  // slot reused by a new connection
  check(attack.on_timer(0).bytes.size() == 4096,
        "a new connection starts its hello from the beginning");
}

static void test_an_alert_is_not_a_hold() {
  Config cfg = make_config();
  SlowTls attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);
  // alert record: type, version, length, level=fatal, description=40
  const char alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
  Action a = attack.on_readable(0, alert, sizeof(alert));
  check(a.kind == Action::Kind::Reconnect, "an alert ends the connection");
  check(attack.alerted() == 1, "and is counted as a refusal");
  check(attack.first_alert() == 40,
        "recording which alert, because handshake_failure and "
        "no_application_protocol mean different things");
  check(attack.summary().find("refused") != std::string::npos,
        "the summary says the handshake was not held");
}

static void test_summary_without_an_alert_claims_only_the_hold() {
  Config cfg = make_config();
  SlowTls attack(cfg);
  check(attack.summary().empty(), "a run that reached nothing describes nothing");
  attack.on_open(0);
  attack.on_connect(0);
  const std::string s = attack.summary();
  check(!s.empty() && s.find("refused") != std::string::npos,
        "with no alert, the summary reports no refusal");
  check(attack.first_alert() == -1, "and no alert code was recorded");
}

int main() {
  test_hello_is_well_formed();
  test_padding_is_what_grows_it();
  test_no_sni_for_a_literal_address();
  test_opening_write_declares_the_whole_record();
  test_the_last_byte_is_never_sent();
  test_each_connection_dribbles_independently();
  test_reused_slot_restarts_the_hello();
  test_an_alert_is_not_a_hold();
  test_summary_without_an_alert_claims_only_the_hold();
  if (failures == 0) {
    std::printf("slow_tls: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "slow_tls: %d check(s) failed\n", failures);
  return 1;
}
