// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/engine.hpp"

#include <signal.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "net/address.hpp"
#include "net/socket.hpp"
#include "slowhttp/attack.hpp"
#include "slowhttp/reactor.hpp"

namespace slowhttp {
namespace {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// Consecutive failed connects (with zero successes) after which we stop trying.
// Sized so every candidate address gets a fair number of attempts first.
constexpr long kGiveUpAfterFailures = 64;

// Bounds recursion when an attack answers a read with another read.
constexpr int kMaxActionDepth = 8;

std::atomic<bool> g_stop{false};

void handle_sigint(int) { g_stop.store(true); }

struct Conn {
  ConnId id = -1;
  Socket sock;
  std::string outbuf;
  std::size_t outpos = 0;
  bool active = false;
  bool has_timer = false;
  std::multimap<TimePoint, ConnId>::iterator timer_it;
};

}  // namespace

struct Engine::Impl {
  const Config& cfg;
  Attack& attack;
  ResolvedAddr addr;
  std::unique_ptr<Reactor> reactor;
  std::vector<Conn> conns;
  std::unordered_map<int, ConnId> fd_to_id;
  std::multimap<TimePoint, ConnId> timers;

  TimePoint start{};
  int active_conns = 0;
  long opened_total = 0;
  long peer_closed_total = 0;
  long connect_failed_total = 0;
  long connected_total = 0;

  // Index of the resolved address we are currently dialing. While nothing has
  // ever connected we rotate through the candidates so an IPv6-first "localhost"
  // still reaches an IPv4-only listener; once one works we pin to it.
  std::size_t cand_idx = 0;
  bool address_pinned = false;
  bool logged_window_ = false;
  std::uint64_t bytes_read_total = 0;

  Impl(const Config& c, Attack& a) : cfg(c), attack(a) {}

  const addrinfo* current_addr() const { return addr.candidates()[cand_idx]; }

  void note_connect_success() {
    ++connected_total;
    address_pinned = true;
  }

  void note_connect_failure() {
    ++connect_failed_total;
    if (address_pinned) return;
    const auto& cands = addr.candidates();
    if (cands.size() > 1) cand_idx = (cand_idx + 1) % cands.size();
  }

  unsigned interest_for(const Conn& c) const {
    // Slow read deliberately does not watch for readability: being woken per
    // arriving byte and draining is the opposite of the attack. Hangup and error
    // conditions are still reported by poll() regardless of requested events, so
    // dropping kRead costs no failure detection.
    unsigned i = attack.wants_read_events() ? kRead : kNone;
    if (c.sock.state() == SockState::Connecting) {
      i |= kWrite;  // writable signals connect completion
    } else if (c.outpos < c.outbuf.size()) {
      i |= kWrite;  // bytes still queued
    }
    return i;
  }

  void update_interest(Conn& c) {
    if (c.active && c.sock.fd() >= 0) reactor->modify(c.sock.fd(), interest_for(c));
  }

  void arm_timer(Conn& c, TimePoint when) {
    cancel_timer(c);
    c.timer_it = timers.emplace(when, c.id);
    c.has_timer = true;
  }

  void cancel_timer(Conn& c) {
    if (c.has_timer) {
      timers.erase(c.timer_it);
      c.has_timer = false;
    }
  }

  void open_slot(Conn& c) {
    c.outbuf.clear();
    c.outpos = 0;
    const ConnOptions opts = attack.conn_options(c.id);
    if (!c.sock.start_connect(current_addr(), opts.recv_buffer)) {
      note_connect_failure();
      return;  // retry on a later ramp tick, possibly on the next candidate
    }
    if (opts.recv_buffer > 0 && !logged_window_) {
      logged_window_ = true;
      // Report what the kernel actually granted: it clamps to its own floor and
      // typically reports double the request, so the effective window is bigger
      // than asked. Silently pretending otherwise would misrepresent the test.
      std::fprintf(stderr,
                   "  advertised window: requested %d B, kernel SO_RCVBUF %d B\n",
                   opts.recv_buffer, c.sock.recv_buffer_size());
    }
    fd_to_id[c.sock.fd()] = c.id;
    reactor->add(c.sock.fd(), interest_for(c));
    c.active = true;
    ++active_conns;
    ++opened_total;
    // connect() can succeed synchronously (common on loopback). No writable event
    // would follow, so start the conversation here or the slot would idle forever.
    if (c.sock.state() == SockState::Connected) {
      note_connect_success();
      begin_conversation(c);
    }
  }

  void close_slot(Conn& c) {
    if (!c.active) return;
    cancel_timer(c);
    if (c.sock.fd() >= 0) {
      reactor->remove(c.sock.fd());
      fd_to_id.erase(c.sock.fd());
    }
    c.sock.close();
    c.active = false;
    c.outbuf.clear();
    c.outpos = 0;
    --active_conns;
    attack.on_close(c.id);
  }

  void flush(Conn& c) {
    while (c.outpos < c.outbuf.size()) {
      long n = c.sock.send_some(c.outbuf.data() + c.outpos,
                                c.outbuf.size() - c.outpos);
      if (n > 0) {
        c.outpos += static_cast<std::size_t>(n);
      } else if (n == 0) {
        break;  // would block; wait for next writable
      } else {
        close_slot(c);
        return;
      }
    }
    if (c.outpos >= c.outbuf.size()) {
      c.outbuf.clear();
      c.outpos = 0;
    }
    update_interest(c);
  }

  // Reads at most `want` bytes once, feeds them to the attack, and carries out
  // whatever it returns. Returns false if the connection was closed.
  bool read_once(Conn& c, std::size_t want, int depth) {
    if (want == 0) return true;
    char buf[16384];
    const std::size_t n_want = std::min(want, sizeof(buf));
    long n = c.sock.recv_some(buf, n_want);
    if (n > 0) {
      bytes_read_total += static_cast<std::uint64_t>(n);
      apply(c, attack.on_readable(c.id, buf, static_cast<std::size_t>(n)), depth);
      return c.active;
    }
    if (n == 0) {  // server finished the response and closed
      ++peer_closed_total;
      close_slot(c);
      return false;
    }
    if (n == -1) return true;  // nothing buffered yet; try again next tick
    close_slot(c);
    return false;
  }

  // `depth` bounds attack-driven recursion (a read whose result asks to read
  // again), so a misbehaving attack cannot blow the stack.
  void apply(Conn& c, const Action& a, int depth = 0) {
    if (a.kind == Action::Kind::Close || a.kind == Action::Kind::Reconnect) {
      close_slot(c);
      return;
    }
    if (a.kind == Action::Kind::Send) c.outbuf += a.bytes;
    if (a.rearm && c.active) arm_timer(c, Clock::now() + *a.rearm);
    if (!c.active) return;
    if (a.kind == Action::Kind::Read && depth < kMaxActionDepth) {
      if (!read_once(c, a.read_bytes, depth + 1)) return;
    }
    if (c.sock.state() == SockState::Connected && c.outpos < c.outbuf.size())
      flush(c);
    else
      update_interest(c);
  }

  // Hands the freshly connected socket to the attack for its opening bytes.
  void begin_conversation(Conn& c) {
    attack.on_open(c.id);
    apply(c, attack.on_connect(c.id));
  }

  void on_writable(Conn& c) {
    if (c.sock.state() == SockState::Connecting) {
      if (!c.sock.finish_connect()) {
        note_connect_failure();
        close_slot(c);
        return;
      }
      note_connect_success();
      begin_conversation(c);
      if (!c.active) return;
    }
    if (c.sock.state() == SockState::Connected && c.outpos < c.outbuf.size())
      flush(c);
  }

  void on_readable(Conn& c) {
    char buf[4096];
    for (;;) {
      long n = c.sock.recv_some(buf, sizeof(buf));
      if (n > 0) {
        bytes_read_total += static_cast<std::uint64_t>(n);
        apply(c, attack.on_readable(c.id, buf, static_cast<std::size_t>(n)));
        if (!c.active) return;
      } else if (n == 0) {
        ++peer_closed_total;
        close_slot(c);
        return;
      } else if (n == -1) {
        return;  // would block
      } else {
        close_slot(c);
        return;
      }
    }
  }

  Conn* conn_by_fd(int fd) {
    auto it = fd_to_id.find(fd);
    if (it == fd_to_id.end()) return nullptr;
    return &conns[static_cast<std::size_t>(it->second)];
  }

  void ramp(TimePoint now) {
    long elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
    // Allow an initial burst of `rate`, then `rate` more per elapsed second.
    long allowance = cfg.rate + (elapsed_ms * cfg.rate) / 1000;
    for (auto& c : conns) {
      if (active_conns >= cfg.connections) break;
      if (opened_total >= allowance) break;
      if (!c.active) open_slot(c);
    }
  }

  void fire_timers(TimePoint now) {
    while (!timers.empty() && timers.begin()->first <= now) {
      ConnId id = timers.begin()->second;
      timers.erase(timers.begin());
      Conn& c = conns[static_cast<std::size_t>(id)];
      c.has_timer = false;
      if (c.active) apply(c, attack.on_timer(id));
    }
  }

  void status_line(TimePoint now) {
    int connecting = 0, connected = 0;
    for (auto& c : conns) {
      if (!c.active) continue;
      if (c.sock.state() == SockState::Connecting)
        ++connecting;
      else
        ++connected;
    }
    long elapsed =
        std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
    std::fprintf(stderr,
                 "\r[%4lds] target=%d active=%d (connecting=%d connected=%d)"
                 " peer_closed=%ld connect_failed=%ld read=%lluB   ",
                 elapsed, cfg.connections, active_conns, connecting, connected,
                 peer_closed_total, connect_failed_total,
                 static_cast<unsigned long long>(bytes_read_total));
    std::fflush(stderr);
  }

  int run() {
    if (cfg.target.tls()) {
      std::fprintf(stderr,
                   "Error: https targets need the TLS backend, which lands in M1."
                   " Use an http:// URL for now.\n");
      return 2;
    }
    std::string err;
    if (!addr.resolve(cfg.target.host, cfg.target.port, err)) {
      std::fprintf(stderr, "Error: cannot resolve %s:%s (%s)\n",
                   cfg.target.host.c_str(), cfg.target.port.c_str(), err.c_str());
      return 2;
    }
    reactor = Reactor::create();
    conns.resize(static_cast<std::size_t>(cfg.connections));
    for (std::size_t i = 0; i < conns.size(); ++i)
      conns[i].id = static_cast<ConnId>(i);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_sigint);

    std::fprintf(stderr,
                 "slowhttptest-ng: %s -> %s://%s:%s%s\n"
                 "  resolved to %s (%zu candidate(s))\n"
                 "  connections=%d rate=%d/s interval=%llds duration=%llds\n"
                 "  (authorized testing only)\n\n",
                 attack.name(), cfg.target.scheme.c_str(), cfg.target.host.c_str(),
                 cfg.target.port.c_str(), cfg.target.path.c_str(),
                 ResolvedAddr::describe(current_addr()).c_str(),
                 addr.candidates().size(), cfg.connections, cfg.rate,
                 static_cast<long long>(cfg.interval.count()),
                 static_cast<long long>(cfg.duration.count()));

    start = Clock::now();
    TimePoint end = start + cfg.duration;
    TimePoint last_status = start;
    std::vector<IoEvent> events;

    bool gave_up = false;
    while (!g_stop.load()) {
      TimePoint now = Clock::now();
      if (now >= end) break;
      ramp(now);

      // Fail fast instead of burning the whole duration against a target that is
      // simply not there (wrong port, nothing listening, every candidate refused).
      if (connected_total == 0 &&
          connect_failed_total >= kGiveUpAfterFailures) {
        gave_up = true;
        break;
      }

      TimePoint next = end;
      if (!timers.empty()) next = std::min(next, timers.begin()->first);
      next = std::min(next, last_status + std::chrono::milliseconds(250));
      auto timeout =
          std::chrono::duration_cast<std::chrono::milliseconds>(next - now);
      if (timeout.count() < 0) timeout = std::chrono::milliseconds(0);

      events.clear();
      reactor->wait(events, timeout);

      for (const auto& ev : events) {
        Conn* c = conn_by_fd(ev.fd);
        if (!c || !c->active) continue;
        if (ev.error) {
          if (c->sock.state() == SockState::Connecting)
            note_connect_failure();
          else
            ++peer_closed_total;
          close_slot(*c);
          continue;
        }
        if (ev.writable) on_writable(*c);
        if (c->active && ev.readable) on_readable(*c);
      }

      now = Clock::now();
      fire_timers(now);
      if (now - last_status >= std::chrono::seconds(1)) {
        status_line(now);
        last_status = now;
      }
    }

    status_line(Clock::now());
    const char* why = gave_up      ? "giving up"
                      : g_stop.load() ? "interrupted"
                                      : "duration reached";
    std::fprintf(stderr,
                 "\n\nDone (%s). opened=%ld connected=%ld peer_closed=%ld"
                 " connect_failed=%ld\n",
                 why, opened_total, connected_total, peer_closed_total,
                 connect_failed_total);

    // Never report success for a test that never reached the target: a silent
    // exit 0 here would make CI and scripts treat an unreachable host as a pass.
    if (connected_total == 0) {
      std::fprintf(stderr,
                   "\nERROR: no connection was ever established to %s:%s"
                   " (tried %zu resolved address(es)).\n"
                   "       The target may be down, firewalled, or on another"
                   " port -- nothing was actually tested.\n",
                   cfg.target.host.c_str(), cfg.target.port.c_str(),
                   addr.candidates().size());
      return 3;
    }
    return 0;
  }
};

Engine::Engine(const Config& cfg, Attack& attack)
    : impl_(new Impl(cfg, attack)) {}
Engine::~Engine() = default;
int Engine::run() { return impl_->run(); }

}  // namespace slowhttp
