// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_PROBE_HPP_
#define SLOWHTTP_PROBE_HPP_

#include <chrono>
#include <functional>
#include <memory>
#include <string>

#include "slowhttp/config.hpp"
#include "slowhttp/event_log.hpp"

namespace slowhttp {

class TlsContext;

// Measures whether the target is still serving ordinary clients, which is the
// only question the report actually answers. Everything else the tool prints —
// sockets held, bytes sent — describes the attacker's side and says nothing
// about whether anyone was denied service.
//
// Runs one short-lived connection at a time on the engine's reactor: connect,
// send a complete and entirely ordinary request, and time the first response
// byte. Never more than one probe in flight, so the measurement itself adds
// negligible load and can't be mistaken for part of the attack.
class Prober {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  Prober(const Config& cfg, std::shared_ptr<TlsContext> tls);
  ~Prober();
  Prober(const Prober&) = delete;
  Prober& operator=(const Prober&) = delete;

  // Resolves the probe endpoint. Returns false and sets `error` on failure; the
  // engine treats that as "no probing", not as a fatal error, so a test still
  // runs when only the probe path is broken.
  // `family` is AF_UNSPEC/AF_INET/AF_INET6, matching -4/-6.
  //
  // `pinned_host` is the address the attack settled on, in numeric form, and
  // exists because the probe is the oracle the verdict rests on. Resolving the
  // target a second time is not harmless: a dual-stack name can hand the probe
  // a different address from the one under attack, and then the run measures
  // one endpoint and reports on another. Observed: the attack pinned ::1 where
  // nothing listened and every connection was refused, while the probe reached
  // the IPv4 address and reported the service available.
  //
  // Ignored when the probe goes through a proxy, where it is connecting
  // somewhere else on purpose.
  // Where the probe will actually connect, in numeric form, once started.
  // Printed at startup and asserted by the tests: the probe is the oracle the
  // verdict rests on, so "it goes where the attack goes" has to be checkable
  // rather than merely intended.
  std::string endpoint() const;

  bool start(std::string& error, int family = 0,
             const std::string& pinned_host = std::string());

  // Reports each completed measurement. Set before the first tick().
  std::function<void(const ProbeSample&)> on_sample;

  // Where finished probe descriptors go. Set by the engine to hand them to the
  // same close pool the attack connections use; left unset, the probe closes
  // them itself.
  //
  // The probe is the measurement clock, and close(2) is not reliably cheap: on
  // macOS a socket a content filter has attached to holds close for up to
  // net.cfil.close_wait_timeout, a second by default. Closing on the event loop
  // would put that delay between a probe finishing and the next one starting,
  // which is measurement error introduced by the instrument. Measured at 0.038
  // ms mean on loopback with a filter active, so this is insurance against a
  // case that has not been reproduced here rather than a repair.
  //
  // The callee takes ownership of the descriptor.
  std::function<void(int fd)> hand_off_fd;

  // Wall-clock origin for ProbeSample::t.
  void set_epoch(TimePoint t) { epoch_ = t; }

  // Descriptive latency floor: probes slower than this count as degraded. The
  // engine raises it once a baseline exists so a merely slow target doesn't read
  // as degraded from the first sample.
  void set_degraded_above(std::chrono::milliseconds ms) { degraded_above_ = ms; }

  // Whether new probes are launched. Paused during a capacity step's ramp so a
  // sample never straddles two connection levels.
  void set_active(bool on) { active_ = on; }

  // Descriptive label attached to samples, e.g. "level 96". Empty for none.
  void set_tag(std::string tag) { tag_ = std::move(tag); }

  // Advances the state machine: starts a probe when one is due, and gives up on
  // one that has outlived the timeout.
  void tick(TimePoint now);

  // Feeds reactor readiness for the probe's own socket.
  void on_event(TimePoint now, bool readable, bool writable, bool error);

  // Reactor registration the engine should reconcile against. -1 == none.
  int fd() const;
  unsigned interest() const;

  // True while a measurement is in flight. A capacity level waits for this to
  // clear before it closes its books, so a probe launched under one connection
  // level is never counted against the next one. Bounded by the probe timeout.
  bool busy() const;

  // Only meaningful once a probe has completed over TLS.
  const std::string& tls_description() const { return tls_description_; }

 private:
  void launch(TimePoint now);
  // Walks the connection setup chain and pushes out the request, as far as it
  // can get without blocking.
  void advance(TimePoint now);
  // Records one completed measurement and schedules the next probe. `status` is
  // the HTTP status code, or -1 when the server never produced a status line.
  void finish(TimePoint now, Availability state, long ms,
              const std::string& detail, int status = -1);

  struct Impl;
  std::unique_ptr<Impl> impl_;
  TimePoint epoch_{};
  std::chrono::milliseconds degraded_above_{1000};
  bool active_ = true;
  std::string tag_;
  std::string tls_description_;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_PROBE_HPP_
