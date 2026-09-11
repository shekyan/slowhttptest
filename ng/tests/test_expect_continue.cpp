// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the Expect: 100-continue state machine.
//
// Two properties define this mode. The request must be *complete* -- headers
// terminated, a body announced -- because a server only commits to receiving a
// body once it has a whole request to look at; withholding the blank line would
// make this slow headers instead. And the body must never begin, because the
// wait is the measurement.
#include <cstdio>
#include <string>

#include "slowhttp/attacks/expect_continue.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::ExpectContinue;

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
  cfg.mode = slowhttp::Mode::ExpectContinue;
  cfg.target.host = "example.test";
  cfg.target.path = "/upload";
  cfg.content_length = 65536;
  return cfg;
}

static void test_request_shape() {
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  Action a = attack.on_connect(0);

  check(a.kind == Action::Kind::Send, "on_connect sends the request");
  const std::string& req = a.bytes;
  check(req.rfind("POST /upload HTTP/1.1\r\n", 0) == 0, "defaults to POST");
  check(req.find("Expect: 100-continue\r\n") != std::string::npos,
        "asks the server whether to send the body");
  check(req.find("Content-Length: 65536\r\n") != std::string::npos,
        "announces a body, or there is nothing to expect");
  // The blank line is the difference from slow headers: the request is finished
  // and the server has everything it needs to decide.
  const std::size_t end = req.find("\r\n\r\n");
  check(end != std::string::npos, "the header block is terminated");
  check(end + 4 == req.size(), "and nothing follows it -- no body is sent");
}

static void test_timer_sends_nothing() {
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);
  Action t = attack.on_timer(0);
  check(t.kind != Action::Kind::Send,
        "the timer sends nothing; a fragment here would make this slow body");
  check(static_cast<bool>(t.rearm), "the timer re-arms so the hold continues");
}

static void test_interim_response_holds() {
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  const std::string interim = "HTTP/1.1 100 Continue\r\n\r\n";
  Action a = attack.on_readable(0, interim.data(), interim.size());
  check(a.kind == Action::Kind::Idle,
        "100 Continue keeps the connection: the commitment is the measurement");
  check(attack.continued() == 1, "and is counted as an invitation");
  check(attack.answered() == 0, "with nothing answered outright");
}

static void test_final_response_ends_the_hold() {
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  const std::string final_ = "HTTP/1.1 417 Expectation Failed\r\n\r\n";
  Action a = attack.on_readable(0, final_.data(), final_.size());
  check(a.kind == Action::Kind::Reconnect,
        "a final status ends the hold, so the slot is recycled");
  check(attack.answered() == 1, "and is counted as answered outright");
  check(attack.continued() == 0, "with no invitation recorded");
}

static void test_status_line_split_across_reads() {
  // TCP splits wherever it likes, and a status line arriving in pieces must not
  // be missed -- missing the 100 would understate what the server committed.
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  const std::string interim = "HTTP/1.1 100 Continue\r\n\r\n";
  for (std::size_t i = 0; i < interim.size(); ++i)
    attack.on_readable(0, interim.data() + i, 1);
  check(attack.continued() == 1, "100 Continue found one byte at a time");
}

static void test_interim_then_final() {
  // The server may invite a body and later give up on it. Both happen on one
  // connection, and the second one ends the hold.
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  const std::string interim = "HTTP/1.1 100 Continue\r\n\r\n";
  attack.on_readable(0, interim.data(), interim.size());
  const std::string timeout = "HTTP/1.1 408 Request Timeout\r\n\r\n";
  Action a = attack.on_readable(0, timeout.data(), timeout.size());
  check(a.kind == Action::Kind::Reconnect, "the later final status ends it");
  check(attack.continued() == 1 && attack.answered() == 1,
        "both are counted, because both happened");
}

static void test_peer_close_recycles_the_slot() {
  // A zero-length read is the peer hanging up. The slot has to come back, or a
  // server that closes on every attempt would quietly drain the run down to no
  // connections at all while still reporting a hold.
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);
  Action a = attack.on_readable(0, "", 0);
  check(a.kind == Action::Kind::Reconnect, "a closed peer frees the slot");
  check(attack.answered() == 0,
        "a close is not an answer -- the server said nothing");
}

static void test_state_is_reset_between_connections() {
  // Slots are reused. A partial status line left over from the previous
  // connection must not be spliced onto the next one's first read.
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);
  attack.on_readable(0, "HTTP/1.1 10", 11);  // truncated, then the peer drops
  attack.on_open(0);                         // slot reused
  Action a = attack.on_readable(0, "0 Continue\r\n\r\n", 14);
  check(attack.continued() == 0,
        "leftovers from the last connection do not form a status line");
  check(a.kind == Action::Kind::Reconnect,
        "the stray line is classified on its own, as a non-1xx");
}

static void test_each_reuse_counts_its_own_invitation() {
  // continued() counts connections the server invited to send a body, and a
  // reused slot is a new connection. Carrying the old flag over would report a
  // single invitation for a server that issued one every time.
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  const std::string interim = "HTTP/1.1 100 Continue\r\n\r\n";
  for (int i = 0; i < 3; ++i) {
    attack.on_open(0);
    attack.on_connect(0);
    attack.on_readable(0, interim.data(), interim.size());
  }
  check(attack.continued() == 3, "every invitation on a reused slot is counted");
}

static void test_summary_says_nothing_without_a_connection() {
  Config cfg = make_config();
  ExpectContinue attack(cfg);
  check(attack.summary().empty(),
        "a run that reached nothing describes nothing");
}

int main() {
  test_request_shape();
  test_timer_sends_nothing();
  test_interim_response_holds();
  test_final_response_ends_the_hold();
  test_status_line_split_across_reads();
  test_interim_then_final();
  test_peer_close_recycles_the_slot();
  test_state_is_reset_between_connections();
  test_each_reuse_counts_its_own_invitation();
  test_summary_says_nothing_without_a_connection();
  if (failures == 0) {
    std::printf("expect_continue: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "expect_continue: %d check(s) failed\n", failures);
  return 1;
}
