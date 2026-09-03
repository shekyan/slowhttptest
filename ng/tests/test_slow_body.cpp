// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the slow-body (R-U-Dead-Yet) state machine. Its defining
// property -- and the one worth guarding -- is that the HEADERS are complete
// while the BODY is withheld. Invert that and the attack degrades into Slowloris
// and starts tripping header timeouts it is supposed to slip past.
#include <cstdio>
#include <cstdlib>
#include <string>

#include "slowhttp/attacks/slow_body.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::SlowBody;

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
  cfg.mode = slowhttp::Mode::SlowBody;
  cfg.target.host = "example.test";
  cfg.target.path = "/submit";
  cfg.content_length = 100000;
  cfg.max_random_data_len = 8;
  return cfg;
}

static void test_request_shape() {
  Config cfg = make_config();
  SlowBody attack(cfg);
  attack.on_open(0);

  Action a = attack.on_connect(0);
  check(a.kind == Action::Kind::Send, "on_connect sends the headers");
  check(static_cast<bool>(a.rearm), "on_connect arms the dribble timer");

  const std::string& req = a.bytes;
  check(req.rfind("POST /submit HTTP/1.1\r\n", 0) == 0, "defaults to POST");
  check(req.find("Content-Length: 100000\r\n") != std::string::npos,
        "declares the large Content-Length the server will wait for");
  // The headers must terminate: that is what makes header timeouts irrelevant.
  check(req.find("\r\n\r\n") != std::string::npos,
        "HEADERS are complete (terminated) -- defeats header timeouts");
  // ...but the body must not be finished.
  const std::size_t body_start = req.find("\r\n\r\n") + 4;
  const std::string body = req.substr(body_start);
  check(!body.empty() && body.size() < static_cast<std::size_t>(cfg.content_length),
        "opening body is far shorter than the promised Content-Length");
}

static void test_dribble() {
  Config cfg = make_config();
  SlowBody attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  Action t = attack.on_timer(0);
  check(t.kind == Action::Kind::Send, "timer dribbles more body");
  check(static_cast<bool>(t.rearm), "timer re-arms");
  check(t.bytes.rfind("&", 0) == 0 && t.bytes.find('=') != std::string::npos,
        "body chunk is a '&name=value' pair");
  check(t.bytes.find("\r\n") == std::string::npos,
        "body chunk carries no CRLF, which would end the request");
}

static void test_never_completes_body() {
  // With a tiny Content-Length the dribble would otherwise finish the request and
  // hand the server a complete POST to answer. It must reconnect instead.
  Config cfg = make_config();
  cfg.content_length = 40;
  cfg.max_random_data_len = 4;
  SlowBody attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  bool reconnected = false;
  for (int i = 0; i < 200; ++i) {
    Action t = attack.on_timer(0);
    if (t.kind == Action::Kind::Reconnect) {
      reconnected = true;
      break;
    }
  }
  check(reconnected,
        "reconnects rather than completing the body and releasing the server");
}

static void test_response_triggers_reconnect() {
  Config cfg = make_config();
  SlowBody attack(cfg);
  attack.on_open(0);
  Action r = attack.on_readable(0, "HTTP/1.1 408\r\n", 14);
  check(r.kind == Action::Kind::Reconnect,
        "a server response means the hold ended; reconnect");
}


// --chunked replaces the Content-Length promise with chunked framing. The hold
// then rests entirely on the terminating zero-length chunk never being sent, so
// that is the property these guard.
static Config make_chunked_config() {
  Config cfg = make_config();
  cfg.chunked = true;
  return cfg;
}

// Framing tested directly, including the case the state machine cannot reach.
static void test_chunk_framing_primitive() {
  using slowhttp::chunk_frame;
  check(chunk_frame("foo=bar") == "7\r\nfoo=bar\r\n",
        "chunk_frame: size in hex, CRLF-delimited");
  check(chunk_frame(std::string(255, 'x')).rfind("ff\r\n", 0) == 0,
        "chunk_frame: size is lowercase hex, not decimal");
  check(chunk_frame(std::string(4096, 'x')).rfind("1000\r\n", 0) == 0,
        "chunk_frame: multi-digit hex sizes are correct");
  // The invariant the whole attack rests on. An empty fragment must not become
  // "0\r\n\r\n", which would complete the request and release the server.
  check(chunk_frame("").empty(),
        "chunk_frame: an empty fragment yields nothing, never a terminating chunk");
}

static void test_chunked_request_shape() {
  Config cfg = make_chunked_config();
  SlowBody attack(cfg);
  attack.on_open(0);
  const std::string req = attack.on_connect(0).bytes;

  check(req.find("Transfer-Encoding: chunked\r\n") != std::string::npos,
        "chunked: announces chunked transfer encoding");
  // Both headers together is the request-smuggling desync of RFC 9112 6.1, and
  // servers that reject the pair would look like targets defending themselves.
  check(req.find("Content-Length:") == std::string::npos,
        "chunked: sends no Content-Length alongside Transfer-Encoding");
  check(req.find("\r\n\r\n") != std::string::npos,
        "chunked: HEADERS are still complete");

  const std::string body = req.substr(req.find("\r\n\r\n") + 4);
  check(body.rfind("7\r\nfoo=bar\r\n", 0) == 0,
        "chunked: opening body is framed as a correctly sized chunk");
}

static void test_chunked_dribble_framing() {
  Config cfg = make_chunked_config();
  SlowBody attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  for (int i = 0; i < 50; ++i) {
    const std::string c = attack.on_timer(0).bytes;
    const std::size_t crlf = c.find("\r\n");
    check(crlf != std::string::npos, "chunked: dribble carries a size line");
    if (crlf == std::string::npos) return;
    // Declared size must match what actually follows, or the server desyncs and
    // the connection dies -- silently ending the hold this attack exists for.
    const std::size_t declared =
        static_cast<std::size_t>(std::strtoul(c.substr(0, crlf).c_str(), nullptr, 16));
    check(c.size() == crlf + 2 + declared + 2,
          "chunked: declared chunk size matches the bytes that follow");
    check(c.substr(c.size() - 2) == "\r\n", "chunked: chunk is CRLF-terminated");
    check(declared > 0, "chunked: never emits a zero-length (terminating) chunk");
  }
}

static void test_chunked_never_terminates() {
  // The whole hold rests on this. A tiny -s used to force a reconnect before the
  // body completed; under chunked framing nothing is promised, so there is no
  // length to complete and the connection should simply be held.
  Config cfg = make_chunked_config();
  cfg.content_length = 40;
  cfg.max_random_data_len = 4;
  SlowBody attack(cfg);
  attack.on_open(0);
  attack.on_connect(0);

  for (int i = 0; i < 500; ++i) {
    Action t = attack.on_timer(0);
    check(t.kind == Action::Kind::Send,
          "chunked: holds the connection instead of recycling on -s");
    if (t.kind != Action::Kind::Send) return;
    check(t.bytes.find("0\r\n\r\n") == std::string::npos,
          "chunked: never sends the terminating chunk");
  }
}

int main() {
  test_request_shape();
  test_dribble();
  test_never_completes_body();
  test_response_triggers_reconnect();
  test_chunk_framing_primitive();
  test_chunked_request_shape();
  test_chunked_dribble_framing();
  test_chunked_never_terminates();
  if (failures == 0) {
    std::printf("slow_body: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "slow_body: %d check(s) failed\n", failures);
  return 1;
}
