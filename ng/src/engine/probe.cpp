// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/probe.hpp"

#include <algorithm>
#include <cstdio>
#include <string>

#include "net/address.hpp"
#include "net/socket.hpp"
#include "slowhttp/reactor.hpp"
#include "slowhttp/tls.hpp"

namespace slowhttp {
namespace {

// The probe deliberately looks like an ordinary client: a complete request,
// Connection: close, no keep-alive games. If it looked unusual a WAF could treat
// it differently from the traffic we are claiming to measure.
std::string build_probe_request(const Config& cfg, bool through_proxy) {
  std::string target = through_proxy && !cfg.target.tls()
                           ? cfg.target.scheme + "://" +
                                 cfg.target.authority() + cfg.target.path
                           : cfg.target.path;
  std::string req;
  req.reserve(256);
  req += "GET ";
  req += target;
  req += " HTTP/1.1\r\n";
  req += "Host: " + cfg.target.host_header() + "\r\n";
  // Exactly the run's User-Agent, with nothing appended to mark it as the probe.
  // A distinguishable probe is the confound the report's own caveats warn about:
  // a WAF could shed the attack traffic while still serving the probe, and the
  // tool would then report "held" for a service that was not serving anyone else.
  // The tool still identifies itself here -- the agent and the Referer say so --
  // it just does not look like a different client than the one under test.
  req += "User-Agent: " + cfg.user_agent + "\r\n";
  req += "Accept: */*\r\n";
  // The probe carries the caller's cookie and -1 headers too. Without them an
  // authenticated or host-routed target would answer the probe from a different
  // code path than the one under attack, and the verdict would describe the
  // wrong endpoint.
  req += cfg.caller_headers();
  req += "Connection: close\r\n";
  req += "\r\n";
  return req;
}

// Pulls NNN out of "HTTP/1.1 NNN Reason". Returns -1 for anything that is not a
// recognizable status line, which is itself worth knowing.
int parse_status_code(const std::string& status_line) {
  if (status_line.rfind("HTTP/", 0) != 0) return -1;
  const auto sp = status_line.find(' ');
  if (sp == std::string::npos || status_line.size() < sp + 4) return -1;
  int code = 0;
  for (std::size_t i = sp + 1; i < sp + 4; ++i) {
    const char c = status_line[i];
    if (c < '0' || c > '9') return -1;
    code = code * 10 + (c - '0');
  }
  return code;
}

std::string build_connect_request(const Config& cfg) {
  const std::string authority = cfg.target.authority();
  return "CONNECT " + authority + " HTTP/1.1\r\n" + "Host: " + authority +
         "\r\n" + "User-Agent: " + cfg.user_agent + "\r\n" +
         "Proxy-Connection: keep-alive\r\n\r\n";
}

}  // namespace

struct Prober::Impl {
  enum class Phase { Idle, Connecting, Sending, Waiting };

  const Config& cfg;
  std::shared_ptr<TlsContext> tls;
  ResolvedAddr addr;
  std::size_t cand_idx = 0;

  Socket sock;
  Phase phase = Phase::Idle;
  TimePoint next_launch{};
  TimePoint started{};        // when the current probe opened its socket
  std::string request;
  std::size_t sent = 0;
  bool through_proxy = false;
  unsigned want = kNone;

  explicit Impl(const Config& c, std::shared_ptr<TlsContext> t)
      : cfg(c), tls(std::move(t)) {}

  const addrinfo* current() const { return addr.candidates()[cand_idx]; }

  void next_candidate() {
    const auto& c = addr.candidates();
    if (c.size() > 1) cand_idx = (cand_idx + 1) % c.size();
  }
};

Prober::Prober(const Config& cfg, std::shared_ptr<TlsContext> tls)
    : impl_(new Impl(cfg, std::move(tls))) {}

Prober::~Prober() = default;

bool Prober::start(std::string& error, int family,
                   const std::string& pinned_host) {
  const Config& cfg = impl_->cfg;
  // -e wins over -d for probe traffic: naming a probe proxy explicitly is a
  // statement about where availability should be measured from.
  const ProxyEndpoint& via =
      cfg.probe_proxy.enabled() ? cfg.probe_proxy : cfg.proxy;
  impl_->through_proxy = via.enabled();

  // Straight to the address the attack chose when there is no proxy in the
  // way, so both halves of the run are measuring the same machine.
  const std::string host = via.enabled()
                               ? via.host
                               : (pinned_host.empty() ? cfg.target.host
                                                      : pinned_host);
  const std::string port = via.enabled() ? via.port : cfg.target.port;
  if (!impl_->addr.resolve(host, port, error, family)) return false;

  impl_->request = build_probe_request(cfg, impl_->through_proxy);
  degraded_above_ = cfg.degraded_above;
  return true;
}

std::string Prober::endpoint() const {
  return ResolvedAddr::describe(impl_->current());
}

int Prober::fd() const {
  return impl_->phase == Impl::Phase::Idle ? -1 : impl_->sock.fd();
}

unsigned Prober::interest() const {
  return impl_->phase == Impl::Phase::Idle ? kNone : impl_->want;
}

bool Prober::busy() const { return impl_->phase != Impl::Phase::Idle; }

void Prober::tick(TimePoint now) {
  Impl& p = *impl_;

  if (p.phase != Impl::Phase::Idle) {
    // A probe that has not answered within the timeout *is* the finding: the
    // service did not serve a client. Report it and free the slot.
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - p.started);
    if (elapsed >= p.cfg.probe_timeout) {
      char buf[96];
      std::snprintf(buf, sizeof(buf), "no response within %lld ms",
                    static_cast<long long>(p.cfg.probe_timeout.count() * 1000));
      finish(now, Availability::Denied, -1, buf);
    }
    return;
  }

  if (!active_) return;
  if (now < p.next_launch) return;
  launch(now);
}

void Prober::launch(TimePoint now) {
  Impl& p = *impl_;
  p.sent = 0;

  SetupPlan plan;
  if (p.through_proxy && p.cfg.target.tls()) plan.connect_request =
      build_connect_request(p.cfg);
  if (p.cfg.target.tls()) {
    plan.tls = p.tls;
    plan.sni = p.cfg.target.host;
  }

  if (!p.sock.start_connect(p.current(), 0, plan)) {
    p.next_candidate();
    // A refused connect is itself a denial of service to this client, so it is
    // recorded rather than retried silently.
    p.started = now;
    p.phase = Impl::Phase::Connecting;
    finish(now, Availability::Denied, -1, "connect failed immediately");
    return;
  }
  p.started = now;
  p.phase = Impl::Phase::Connecting;
  p.want = kWrite;
  // A synchronous connect (common on loopback) produces no writable event.
  if (p.sock.state() != SockState::Connecting) advance(now);
}

void Prober::advance(TimePoint now) {
  Impl& p = *impl_;

  // Walk the setup chain (proxy CONNECT, TLS) before any HTTP is sent.
  while (!p.sock.ready()) {
    switch (p.sock.continue_setup()) {
      case SetupIo::Done:
        break;
      case SetupIo::WantRead:
        p.want = kRead;
        return;
      case SetupIo::WantWrite:
        p.want = kWrite;
        return;
      case SetupIo::Error:
      default:
        finish(now, Availability::Denied, -1,
               p.sock.setup_error().empty() ? "connection setup failed"
                                            : p.sock.setup_error());
        return;
    }
  }
  if (tls_description_.empty()) tls_description_ = p.sock.tls_description();

  p.phase = Impl::Phase::Sending;
  while (p.sent < p.request.size()) {
    long n = p.sock.send_some(p.request.data() + p.sent, p.request.size() - p.sent);
    if (n > 0) {
      p.sent += static_cast<std::size_t>(n);
    } else if (n == 0) {
      p.want = kWrite;
      return;
    } else {
      finish(now, Availability::Denied, -1, "send failed");
      return;
    }
  }
  p.phase = Impl::Phase::Waiting;
  p.want = kRead;
}

void Prober::on_event(TimePoint now, bool readable, bool writable, bool error) {
  Impl& p = *impl_;
  if (p.phase == Impl::Phase::Idle) return;

  if (error && p.phase == Impl::Phase::Connecting &&
      p.sock.state() == SockState::Connecting) {
    p.next_candidate();
    finish(now, Availability::Denied, -1, "connection refused or reset");
    return;
  }

  if (p.sock.state() == SockState::Connecting) {
    if (!writable) return;
    if (!p.sock.finish_connect()) {
      p.next_candidate();
      finish(now, Availability::Denied, -1, "connect failed");
      return;
    }
    advance(now);
    return;
  }

  if (!p.sock.ready()) {
    if (readable || writable) advance(now);
    return;
  }

  if (p.phase == Impl::Phase::Sending && writable) {
    advance(now);
    return;
  }

  if (p.phase == Impl::Phase::Waiting && (readable || error)) {
    char buf[2048];
    long n = p.sock.recv_some(buf, sizeof(buf));
    if (n > 0) {
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now - p.started)
                          .count();
      std::string status(buf, static_cast<std::size_t>(
                                  std::min<long>(n, 15)));
      // The status code is deliberately *not* used to decide availability: a 503
      // is a served response, and calling it a denial would conflate "the server
      // answered, refusing" with "the server never answered". It is recorded so
      // the reader can see it, and so --fail-on-status can gate on it.
      auto cut = status.find('\r');
      if (cut != std::string::npos) status.resize(cut);
      const bool slow = ms >= degraded_above_.count();
      finish(now, slow ? Availability::Degraded : Availability::Ok,
             static_cast<long>(ms),
             (slow ? "slow response: " : "") + status,
             parse_status_code(status));
      return;
    }
    if (n == 0) {
      finish(now, Availability::Denied, -1,
             "server closed the connection without responding");
      return;
    }
    if (n == -2) {
      finish(now, Availability::Denied, -1, "connection reset while waiting");
      return;
    }
    // -1: nothing buffered yet, keep waiting for the timeout to decide.
  }
}

void Prober::finish(TimePoint now, Availability state, long ms,
                    const std::string& detail, int status) {
  Impl& p = *impl_;
  // Hand the descriptor off where the engine has provided somewhere to put it,
  // so a slow close cannot sit between this probe and the next. release_fd()
  // detaches it without closing; the pool owns it from here.
  if (hand_off_fd && p.sock.fd() >= 0)
    hand_off_fd(p.sock.release_fd());
  else
    p.sock.close();
  p.phase = Impl::Phase::Idle;
  p.want = kNone;
  // Schedule from the launch time, not from now, so a slow probe doesn't push
  // the whole sampling grid out and quietly lower the resolution.
  p.next_launch = p.started + p.cfg.probe_interval;
  if (p.next_launch < now) p.next_launch = now;

  if (on_sample) {
    ProbeSample s;
    s.t = std::chrono::duration<double>(p.started - epoch_).count();
    s.state = state;
    s.ms = ms;
    s.status = status;
    s.detail = tag_.empty() ? detail : (tag_ + " · " + detail);
    on_sample(s);
  }
}

}  // namespace slowhttp
