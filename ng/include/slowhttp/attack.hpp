// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACK_HPP_
#define SLOWHTTP_ATTACK_HPP_

#include <cstddef>
#include <string>

#include "slowhttp/action.hpp"

namespace slowhttp {

using ConnId = int;

// Socket-level knobs an attack needs applied *before* connect(). SO_RCVBUF in
// particular only shapes the advertised TCP window if it is set before the
// handshake, and it is the entire mechanism behind slow read.
struct ConnOptions {
  int recv_buffer = 0;  // SO_RCVBUF in bytes; 0 leaves the kernel default
};

// A slow-HTTP attack expressed as a per-connection state machine. One instance is
// shared across every connection; per-connection scratch state is keyed by ConnId
// inside the concrete attack (ids are stable slot indices in [0, connections)).
//
// The engine calls these hooks in response to real socket/timer events and then
// carries out the returned Action. Keeping attacks free of any I/O makes each one
// small and unit-testable against a fake driver.
class Attack {
 public:
  virtual ~Attack() = default;

  virtual const char* name() const = 0;

  // Socket options for the next connection on this slot, applied before connect().
  virtual ConnOptions conn_options(ConnId /*id*/) { return {}; }

  // Whether the engine should watch these sockets for readability and drain them.
  // Slow read returns false: being woken on every arriving byte and draining the
  // buffer is the opposite of the attack. Those connections read only when an
  // Action::read() asks. Hangup/error detection is unaffected either way.
  virtual bool wants_read_events() const { return true; }

  // A connection slot has been (re)opened; (re)initialize per-connection state.
  virtual void on_open(ConnId /*id*/) {}

  // The connection finished connecting. Return the first bytes to dribble.
  virtual Action on_connect(ConnId id) = 0;

  // The connection's followup timer fired (armed via Action::rearm).
  virtual Action on_timer(ConnId id) = 0;

  // Bytes arrived from the server. For most slow attacks any response (or EOF,
  // signalled as len == 0) means the server ended our slow request.
  virtual Action on_readable(ConnId id, const char* data, std::size_t len) = 0;

  // The connection slot was closed or dropped.
  virtual void on_close(ConnId /*id*/) {}

  // One line for the end of the run, or empty for none.
  //
  // For a measurement only the attack can make, because it is the only thing
  // that reads the peer. The engine cannot print it from its own counters --
  // it does not know an interim response from any other bytes -- and neither
  // can main(), because run() leaves by _exit().
  virtual std::string summary() const { return std::string(); }

  // An extra status row while the run is live, or empty for none. For modes
  // whose connection count does not mean what the generic label implies:
  // over UDP there is no such thing as a connected socket, so the mode says
  // what is actually known about the target instead.
  virtual std::string status_note() const { return std::string(); }
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACK_HPP_
