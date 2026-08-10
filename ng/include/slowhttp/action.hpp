// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ACTION_HPP_
#define SLOWHTTP_ACTION_HPP_

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>

namespace slowhttp {

using Millis = std::chrono::milliseconds;

// Instruction returned by an Attack telling the engine what to do next for a
// single connection. This is the whole coupling surface between attack logic and
// the I/O engine: attacks decide *what bytes to dribble and when*, the engine
// owns sockets, timers and the event loop.
struct Action {
  enum class Kind { Idle, Send, Read, Close, Reconnect };

  Kind kind = Kind::Idle;
  std::string bytes;            // payload, valid for Kind::Send
  std::optional<Millis> rearm;  // if set, schedule on_timer() after this delay
  std::size_t read_bytes = 0;   // valid for Kind::Read

  static Action idle() { return {}; }
  static Action send(std::string b, std::optional<Millis> next = std::nullopt) {
    Action a;
    a.kind = Kind::Send;
    a.bytes = std::move(b);
    a.rearm = next;
    return a;
  }
  static Action wait(Millis d) {
    Action a;
    a.rearm = d;
    return a;
  }
  // Read at most `n` bytes from the receive buffer, once. Used by slow read to
  // sip the response instead of draining it, so the server's send buffer stays
  // full and it cannot retire the connection.
  static Action read(std::size_t n, std::optional<Millis> next = std::nullopt) {
    Action a;
    a.kind = Kind::Read;
    a.read_bytes = n;
    a.rearm = next;
    return a;
  }
  static Action close() {
    Action a;
    a.kind = Kind::Close;
    return a;
  }
  static Action reconnect() {
    Action a;
    a.kind = Kind::Reconnect;
    return a;
  }
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ACTION_HPP_
