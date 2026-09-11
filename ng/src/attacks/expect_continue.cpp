// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/expect_continue.hpp"

#include "slowhttp/request.hpp"

#include <algorithm>
#include <cstddef>

namespace slowhttp {
namespace {

// A peer that never sends a newline must not be able to grow the per-connection
// buffer without bound. One status line is far shorter than this; anything
// longer is not a status line.
constexpr std::size_t kMaxStatusLine = 8192;

// Whether a status line carries an interim 1xx code. Only the three digits are
// read: the reason phrase is free text and says nothing reliable.
bool is_interim(const std::string& line, int* code_out) {
  if (line.rfind("HTTP/", 0) != 0) return false;
  const std::size_t sp = line.find(' ');
  if (sp == std::string::npos || line.size() < sp + 4) return false;
  int code = 0;
  for (std::size_t i = sp + 1; i < sp + 4; ++i) {
    const char c = line[i];
    if (c < '0' || c > '9') return false;
    code = code * 10 + (c - '0');
  }
  if (code_out) *code_out = code;
  return code >= 100 && code < 200;
}

}  // namespace

ExpectContinue::ExpectContinue(const Config& cfg)
    : cfg_(cfg),
      request_(build_request()),
      interval_(std::chrono::duration_cast<Millis>(cfg.interval)),
      reply_(static_cast<std::size_t>(cfg.connections)),
      got_continue_(static_cast<std::size_t>(cfg.connections), false) {}

void ExpectContinue::on_open(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < reply_.size()) {
    reply_[id].clear();
    got_continue_[id] = false;
  }
}

Action ExpectContinue::on_connect(ConnId /*id*/) {
  ++started_;
  // The whole request goes out at once, headers terminated. Nothing is withheld
  // syntactically -- the request is complete and valid, and the body is the one
  // thing the server has just been told to wait for.
  return Action::send(request_, interval_);
}

Action ExpectContinue::on_timer(ConnId /*id*/) {
  // Nothing follows. Sending a fragment of the body here would turn this into
  // slow body with extra steps; the point is that the body never begins, so the
  // timer only keeps the connection on the engine's books.
  return Action::wait(interval_);
}

bool ExpectContinue::consume(ConnId id, std::string& line) {
  int code = 0;
  if (is_interim(line, &code)) {
    // 100 Continue: the server has committed to receiving a body. Keep holding
    // -- that commitment is the thing being measured.
    if (id >= 0 && static_cast<std::size_t>(id) < got_continue_.size() &&
        !got_continue_[id]) {
      got_continue_[id] = true;
      ++continued_;
    }
    return false;
  }
  // Anything else is a final status: the server answered without waiting for
  // the body, which ends the hold. That is the healthy behaviour, and it is
  // counted rather than treated as a failure.
  ++answered_;
  return true;
}

Action ExpectContinue::on_readable(ConnId id, const char* data,
                                   std::size_t len) {
  if (id < 0 || static_cast<std::size_t>(id) >= reply_.size())
    return Action::idle();
  if (len == 0) return Action::reconnect();  // peer closed

  std::string& buf = reply_[id];
  if (buf.size() < kMaxStatusLine)
    buf.append(data, std::min(len, kMaxStatusLine - buf.size()));

  // A 100 Continue is a complete little response of its own, so more than one
  // status line can arrive on a connection: the interim first, the final later.
  for (;;) {
    const std::size_t eol = buf.find("\r\n");
    if (eol == std::string::npos) break;
    std::string line = buf.substr(0, eol);
    buf.erase(0, eol + 2);
    if (line.empty()) continue;  // the blank line ending an interim response
    if (consume(id, line)) return Action::reconnect();
  }
  return Action::idle();
}

std::string ExpectContinue::summary() const {
  // Sending the interim response is optional (RFC 9110 10.1.1), and an
  // intermediary may answer it itself, forward it, or swallow it. Which of
  // those happened decides what the run actually measured, so it is stated.
  // Nothing reached the target, so there is nothing to say about it. Saying
  // the request is being held would describe a test that did not run.
  if (started_ == 0) return std::string();
  if (continued_ == 0 && answered_ == 0)
    return "  expect 100-continue: the target sent no reply at all -- it is"
           " holding the request without answering";
  char buf[192];
  std::snprintf(buf, sizeof(buf),
                "  expect 100-continue: %ld invited to send a body, %ld"
                " answered outright without waiting for one",
                continued_, answered_);
  return buf;
}

std::string ExpectContinue::build_request() const {
  RequestSpec spec = RequestSpec::from(cfg_);
  // The promise the server is being asked to prepare for. Without a length
  // there is no body to expect, and a server is entitled to answer immediately.
  spec.set("Content-Length", std::to_string(cfg_.content_length));
  spec.set("Content-Type", cfg_.content_type);
  spec.set("Expect", "100-continue");
  spec.set("Connection", "close");
  // The blank line is sent here, unlike slow headers: the request is finished.
  // Everything that follows is the body, and the body is what never comes.
  return spec.serialize_http11() + "\r\n";
}

}  // namespace slowhttp
