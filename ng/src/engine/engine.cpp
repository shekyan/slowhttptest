// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/engine.hpp"

#include <signal.h>
#include <time.h>

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
#include "slowhttp/event_log.hpp"
#include "slowhttp/probe.hpp"
#include "slowhttp/reactor.hpp"
#include "slowhttp/report.hpp"
#include "slowhttp/tls.hpp"

namespace slowhttp {
namespace {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// Consecutive failed connects (with zero successes) after which we stop trying.
// Sized so every candidate address gets a fair number of attempts first.
constexpr long kGiveUpAfterFailures = 64;

// Bounds recursion when an attack answers a read with another read.
constexpr int kMaxActionDepth = 8;

// How often the live status line is refreshed. The event loop also uses this as
// its wake-up deadline, and the two must stay the same value: a loop that waits
// on a shorter grid than it refreshes on gets handed a zero timeout and spins.
constexpr std::chrono::milliseconds kStatusInterval{1000};

// Probes taken before any load is applied. Three is the minimum that lets a
// single unlucky sample be seen as an outlier rather than as the baseline.
constexpr int kBaselineProbes = 3;

// A target's healthy latency times this is the floor for calling a response
// "degraded" -- so a target that is simply slow does not read as degraded from
// the first sample.
constexpr double kDegradedBaselineFactor = 5.0;

// How long to keep probing after the attack stops, watching for recovery.
constexpr std::chrono::seconds kRecoveryWatch{20};

// Give a capacity level's connections this long to come up before the level's
// measurement window opens, so a sample never straddles two levels.
std::chrono::milliseconds ramp_budget(int conns, int rate) {
  long ms = rate > 0 ? (1000L * conns) / rate : 1000L;
  return std::chrono::milliseconds(std::max(500L, ms + 500L));
}

std::atomic<bool> g_stop{false};

void handle_sigint(int) { g_stop.store(true); }

std::string utc_now() {
  time_t now = ::time(nullptr);
  struct tm tm_buf;
#ifdef _WIN32
  gmtime_s(&tm_buf, &now);
#else
  ::gmtime_r(&now, &tm_buf);
#endif
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
  return buf;
}

struct Conn {
  ConnId id = -1;
  Socket sock;
  std::string outbuf;
  std::size_t outpos = 0;
  bool active = false;
  bool has_timer = false;
  // What the setup chain (proxy CONNECT / TLS handshake) is waiting for.
  unsigned setup_want = 0;
  std::multimap<TimePoint, ConnId>::iterator timer_it;
};

// Where the run is in its lifecycle. Baseline and Recovery exist so the report
// can say what the target looked like *without* the attack, on both sides of it;
// without them a slow target and a denied one are indistinguishable.
enum class Phase { Baseline, Attack, Recovery, Finished };

}  // namespace

struct Engine::Impl {
  const Config& cfg;
  Attack& attack;
  ResolvedAddr addr;
  std::unique_ptr<Reactor> reactor;
  std::vector<Conn> conns;
  std::unordered_map<int, ConnId> fd_to_id;
  std::multimap<TimePoint, ConnId> timers;

  std::shared_ptr<TlsContext> tls;
  SetupPlan plan;

  std::unique_ptr<Prober> prober;
  int probe_reg_fd = -1;
  unsigned probe_reg_int = kNone;

  EventLog log;
  Phase phase = Phase::Baseline;

  TimePoint start{};
  TimePoint phase_deadline{};
  int target_conns = 0;         // what ramp() aims for right now
  int active_conns = 0;
  long opened_total = 0;
  long peer_closed_total = 0;
  long connect_failed_total = 0;
  long connected_total = 0;     // TCP connects that succeeded
  long ready_total = 0;         // connections that got past setup (proxy/TLS)
  long setup_failed_total = 0;

  // Capacity staircase state.
  std::size_t level_idx = 0;
  std::vector<int> levels;
  bool level_measuring = false;
  std::size_t level_probe_begin = 0;
  TimePoint level_started{};

  // Index of the resolved address we are currently dialing. While nothing has
  // ever connected we rotate through the candidates so an IPv6-first "localhost"
  // still reaches an IPv4-only listener; once one works we pin to it.
  std::size_t cand_idx = 0;
  bool address_pinned = false;
  bool logged_window_ = false;
  bool logged_tls_ = false;
  std::uint64_t bytes_read_total = 0;
  std::string last_setup_error_;  // kept for the scheme-mismatch hint

  Impl(const Config& c, Attack& a) : cfg(c), attack(a) {}

  double elapsed(TimePoint t) const {
    return std::chrono::duration<double>(t - start).count();
  }

  // Progress and summary output. At -q / -v 0 the run is silent on stdout and
  // stderr and speaks only through its exit code and any report files. Genuine
  // errors are deliberately NOT gated on this: a silent non-zero exit tells the
  // operator nothing about what went wrong.
  bool chatty() const { return cfg.log_level >= 1; }

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
    switch (c.sock.state()) {
      case SockState::Connecting:
        return kWrite;  // writable signals connect completion
      case SockState::ProxyConnect:
      case SockState::TlsHandshake:
        // The setup chain says which readiness it needs; guessing wrong here
        // deadlocks a TLS handshake that wants to write during a read.
        return c.setup_want ? c.setup_want : kRead;
      default:
        break;
    }
    // Slow read deliberately does not watch for readability: being woken per
    // arriving byte and draining is the opposite of the attack. Hangup and error
    // conditions are still reported by poll() regardless of requested events, so
    // dropping kRead costs no failure detection.
    unsigned i = attack.wants_read_events() ? kRead : kNone;
    if (c.outpos < c.outbuf.size()) i |= kWrite;  // bytes still queued
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
    c.setup_want = 0;
    const ConnOptions opts = attack.conn_options(c.id);
    if (!c.sock.start_connect(current_addr(), opts.recv_buffer, plan)) {
      note_connect_failure();
      return;  // retry on a later ramp tick, possibly on the next candidate
    }
    if (opts.recv_buffer > 0 && !logged_window_) {
      logged_window_ = true;
      log.meta.kernel_rcvbuf = c.sock.recv_buffer_size();
      // Report what the kernel actually granted: it clamps to its own floor and
      // typically reports double the request, so the effective window is bigger
      // than asked. Silently pretending otherwise would misrepresent the test.
      if (chatty())
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
    if (c.sock.state() != SockState::Connecting) {
      note_connect_success();
      drive_setup(c);
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

  void close_all() {
    for (auto& c : conns) close_slot(c);
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
    if (c.sock.ready() && c.outpos < c.outbuf.size())
      flush(c);
    else
      update_interest(c);
  }

  // Hands the freshly usable socket to the attack for its opening bytes.
  void begin_conversation(Conn& c) {
    ++ready_total;
    if (!logged_tls_ && cfg.target.tls()) {
      logged_tls_ = true;
      log.meta.tls_description = c.sock.tls_description();
      if (chatty())
        std::fprintf(stderr, "  TLS: %s\n", log.meta.tls_description.c_str());
    }
    attack.on_open(c.id);
    apply(c, attack.on_connect(c.id));
  }

  // Walks proxy CONNECT and the TLS handshake. Until this reaches Done the
  // attack has not been told the connection exists, which is what keeps every
  // attack ignorant of both.
  void drive_setup(Conn& c) {
    for (;;) {
      if (c.sock.ready()) {
        begin_conversation(c);
        return;
      }
      switch (c.sock.continue_setup()) {
        case SetupIo::Done:
          begin_conversation(c);
          return;
        case SetupIo::WantRead:
          c.setup_want = kRead;
          update_interest(c);
          return;
        case SetupIo::WantWrite:
          c.setup_want = kWrite;
          update_interest(c);
          return;
        case SetupIo::Error:
        default:
          ++setup_failed_total;
          if (setup_failed_total == 1 && !c.sock.setup_error().empty()) {
            last_setup_error_ = c.sock.setup_error();
            // Print the first one: a systematically failing handshake or a proxy
            // refusing CONNECT would otherwise look like a target that simply
            // drops connections, which is a completely different finding.
            if (chatty())
              std::fprintf(stderr, "\n  connection setup failed: %s\n",
                         c.sock.setup_error().c_str());
          }
          close_slot(c);
          return;
      }
    }
  }

  void on_writable(Conn& c) {
    if (c.sock.state() == SockState::Connecting) {
      if (!c.sock.finish_connect()) {
        note_connect_failure();
        close_slot(c);
        return;
      }
      note_connect_success();
      drive_setup(c);
      if (!c.active) return;
    } else if (!c.sock.ready()) {
      drive_setup(c);
      if (!c.active) return;
    }
    if (c.sock.ready() && c.outpos < c.outbuf.size()) flush(c);
  }

  void on_readable(Conn& c) {
    if (!c.sock.ready()) {
      drive_setup(c);
      return;
    }
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
    if (target_conns <= 0) return;
    long elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
    // Allow an initial burst of `rate`, then `rate` more per elapsed second.
    long allowance = cfg.rate + (elapsed_ms * cfg.rate) / 1000;
    for (auto& c : conns) {
      if (active_conns >= target_conns) break;
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

  int held_connections() const {
    int held = 0;
    for (const auto& c : conns)
      if (c.active && c.sock.ready()) ++held;
    return held;
  }

  // ---- probe plumbing ----------------------------------------------------

  void sync_probe_registration() {
    if (!prober) return;
    const int want_fd = prober->fd();
    const unsigned want_int = prober->interest();
    if (want_fd != probe_reg_fd) {
      // Only retire the old descriptor if it is still ours. Descriptor numbers
      // are recycled aggressively: once the probe closes one, the very next
      // connection can be handed the same number, and unregistering it here
      // would silently stop the engine from ever hearing about that connection.
      if (probe_reg_fd >= 0 && fd_to_id.find(probe_reg_fd) == fd_to_id.end())
        reactor->remove(probe_reg_fd);
      probe_reg_fd = want_fd;
      probe_reg_int = want_int;
      if (want_fd >= 0) reactor->add(want_fd, want_int);
    } else if (want_fd >= 0 && want_int != probe_reg_int) {
      reactor->modify(want_fd, want_int);
      probe_reg_int = want_int;
    }
  }

  // Raises the "degraded" floor to a multiple of the measured healthy latency,
  // so a target that answers in 400 ms when idle is not reported as degraded for
  // answering in 500 ms under load.
  void calibrate_from_baseline() {
    if (!prober) return;
    std::vector<long> ok;
    for (const auto* p : log.baseline_probes())
      if (p->state == Availability::Ok && p->ms >= 0) ok.push_back(p->ms);
    if (ok.empty()) return;
    std::sort(ok.begin(), ok.end());
    const long median = ok[ok.size() / 2];
    log.meta.baseline_ms = median;
    const auto floor = std::chrono::milliseconds(
        static_cast<long>(median * kDegradedBaselineFactor));
    const auto chosen = std::max(cfg.degraded_above, floor);
    log.meta.degraded_above_ms = chosen.count();
    prober->set_degraded_above(chosen);
  }

  // ---- capacity staircase -------------------------------------------------

  void build_levels() {
    const int ceiling = cfg.capacity.max > 0 ? cfg.capacity.max : cfg.connections;
    for (int n = cfg.capacity.start; n <= ceiling; n += cfg.capacity.step)
      levels.push_back(n);
    if (levels.empty()) levels.push_back(ceiling);
    // The last level must reach the ceiling, or the report would claim a range
    // was tested that never was.
    if (levels.back() != ceiling) levels.push_back(ceiling);
  }

  void enter_level(TimePoint now) {
    target_conns = levels[level_idx];
    level_started = now;
    level_measuring = false;
    if (prober) {
      prober->set_active(false);  // no samples while connections are coming up
      prober->set_tag("level " + std::to_string(target_conns));
    }
    log.note(elapsed(now), Availability::Ok, "Capacity level",
             "ramping to " + std::to_string(target_conns) + " connections");
    phase_deadline = now + ramp_budget(target_conns, cfg.rate);
  }

  void finish_level(TimePoint now) {
    CapacityLevel lvl;
    lvl.connections = levels[level_idx];
    lvl.hold_s = std::chrono::duration<double>(now - level_started).count();
    std::vector<long> served;
    for (std::size_t i = level_probe_begin; i < log.probes.size(); ++i) {
      ++lvl.probes_total;
      const auto& p = log.probes[i];
      if (p.state == Availability::Ok) {
        ++lvl.probes_served;
        served.push_back(p.ms);
      } else if (p.state == Availability::Denied) {
        lvl.denied = true;
      }
    }
    if (!served.empty()) {
      std::sort(served.begin(), served.end());
      lvl.median_ms = served[served.size() / 2];
    }
    // A level where every answered probe was slow but none failed is still a
    // denial of normal service; saying otherwise would overstate the ceiling.
    if (!lvl.denied && lvl.probes_total > 0 && lvl.probes_served == 0)
      lvl.denied = true;
    log.capacity.push_back(lvl);

    if (chatty())
      std::fprintf(stderr, "\n  level %d: %d/%d probes served, median %ld ms -> %s\n",
                 lvl.connections, lvl.probes_served, lvl.probes_total,
                 lvl.median_ms, lvl.denied ? "DENIED" : "held");
    log.note(elapsed(now), lvl.denied ? Availability::Denied : Availability::Ok,
             lvl.denied ? "Level denied" : "Level held",
             std::to_string(lvl.probes_served) + "/" +
                 std::to_string(lvl.probes_total) + " probes served at " +
                 std::to_string(lvl.connections) + " connections");
  }

  // Returns false when the staircase is over.
  bool capacity_tick(TimePoint now) {
    if (!level_measuring) {
      const bool ramped = active_conns >= target_conns;
      if (!ramped && now < phase_deadline) return true;
      level_measuring = true;
      level_probe_begin = log.probes.size();
      if (prober) prober->set_active(true);
      phase_deadline = now + cfg.capacity.hold;
      return true;
    }
    if (now < phase_deadline) return true;
    // Let an in-flight probe land before closing the books: it was launched
    // under this level's load, so counting it against the next one would both
    // understate this level and contaminate the next. The prober's own timeout
    // bounds the wait.
    if (prober && prober->busy()) return true;

    finish_level(now);
    if (log.capacity.back().denied) return false;  // bracket found
    if (++level_idx >= levels.size()) return false;
    enter_level(now);
    return true;
  }

  // ---- run ---------------------------------------------------------------

  // The single most confusing way to misuse this tool is to point it at the
  // right port with the wrong scheme. Both directions look like a target that
  // silently drops everything, and the run "succeeds" while measuring nothing.
  // Neither case can be detected with certainty, so this is phrased as a
  // question and printed alongside the results rather than replacing them.
  void scheme_mismatch_hint() const {
    if (!chatty()) return;

    // http:// against a TLS listener: the handshake we never send means the
    // server closes on our cleartext request, every time, without ever replying.
    if (!cfg.target.tls() && ready_total > 0 && bytes_read_total == 0 &&
        peer_closed_total >= 4) {
      std::fprintf(stderr,
                   "\nHINT: %ld connection(s) were accepted and then closed"
                   " without sending a single byte back.\n"
                   "      That is what a TLS listener does when it is handed a"
                   " cleartext request.\n"
                   "      The URL says http:// -- try https://%s%s\n",
                   peer_closed_total, cfg.target.authority().c_str(),
                   cfg.target.path.c_str());
      return;
    }

    // https:// against a cleartext listener. Two shapes, because it depends on
    // what the server does with a ClientHello it cannot parse.
    if (!cfg.target.tls() || ready_total != 0 || connected_total == 0) return;

    const bool looks_cleartext =
        last_setup_error_.find("wrong version number") != std::string::npos ||
        last_setup_error_.find("packet length") != std::string::npos ||
        last_setup_error_.find("record layer") != std::string::npos;

    if (looks_cleartext) {
      // The server replied with plain HTTP text and OpenSSL rejected it as a
      // malformed record.
      std::fprintf(stderr,
                   "\nHINT: the TLS handshake failed with \"%s\".\n"
                   "      That is what OpenSSL reports when the port answers in"
                   " cleartext.\n"
                   "      The URL says https:// -- try http://%s%s\n",
                   last_setup_error_.c_str(), cfg.target.authority().c_str(),
                   cfg.target.path.c_str());
    } else if (setup_failed_total == 0) {
      // Nothing failed and nothing completed: the handshakes are simply hanging.
      // A cleartext HTTP server does exactly this -- it waits for a blank line
      // that a binary ClientHello never contains, so it never answers at all.
      std::fprintf(stderr,
                   "\nHINT: %ld connection(s) completed TCP but not one TLS"
                   " handshake finished, and none failed either --\n"
                   "      they are all still waiting for a ServerHello. A"
                   " cleartext HTTP server behaves exactly this way,\n"
                   "      because it is waiting for a blank line that a binary"
                   " ClientHello never contains.\n"
                   "      The URL says https:// -- try http://%s%s\n",
                   connected_total, cfg.target.authority().c_str(),
                   cfg.target.path.c_str());
    }
  }

  void status_line(TimePoint now) {
    if (!chatty()) return;
    int connecting = 0, setting_up = 0, held = 0;
    for (auto& c : conns) {
      if (!c.active) continue;
      if (c.sock.state() == SockState::Connecting)
        ++connecting;
      else if (!c.sock.ready())
        ++setting_up;
      else
        ++held;
    }
    long secs =
        std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
    const char* phase_name = phase == Phase::Baseline  ? "baseline"
                             : phase == Phase::Attack  ? "attack  "
                             : phase == Phase::Recovery ? "recovery"
                                                        : "done    ";
    char probe_txt[48] = "  probe=off";
    if (prober && !log.probes.empty()) {
      const auto& p = log.probes.back();
      if (p.ms >= 0)
        std::snprintf(probe_txt, sizeof(probe_txt), "  probe=%s %ldms",
                      availability_name(p.state), p.ms);
      else
        std::snprintf(probe_txt, sizeof(probe_txt), "  probe=%s",
                      availability_name(p.state));
    }
    std::fprintf(stderr,
                 "\r[%4lds %s] target=%d held=%d (connecting=%d setup=%d)"
                 " peer_closed=%ld failed=%ld%s   ",
                 secs, phase_name, target_conns, held, connecting, setting_up,
                 peer_closed_total, connect_failed_total + setup_failed_total,
                 probe_txt);
    std::fflush(stderr);
  }

  bool build_setup_plan(std::string& err) {
    if (cfg.target.tls()) {
      if (!TlsContext::available()) {
        err =
            "https targets need a TLS backend, and this binary was built without"
            " one (-DSLOWHTTP_TLS=OFF). Rebuild with OpenSSL, or use an http://"
            " URL.";
        return false;
      }
      tls = TlsContext::create(/*verify_peer=*/false, err);
      if (!tls) return false;
      plan.tls = tls;
      plan.sni = cfg.target.host;
    }
    if (cfg.proxy.enabled() && cfg.target.tls()) {
      const std::string authority = cfg.target.authority();
      plan.connect_request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " +
                             authority + "\r\nUser-Agent: " + cfg.user_agent +
                             "\r\nProxy-Connection: keep-alive\r\n\r\n";
    }
    return true;
  }

  void fill_meta() {
    log.meta.started_utc = utc_now();
    log.meta.target_url = cfg.target.scheme + "://" + cfg.target.authority() +
                          cfg.target.path;
    switch (cfg.mode) {
      case Mode::SlowHeaders: log.meta.mode_flag = "-H"; break;
      case Mode::SlowBody:    log.meta.mode_flag = "-B"; break;
      case Mode::SlowRead:    log.meta.mode_flag = "-X"; break;
      case Mode::Range:       log.meta.mode_flag = "-R"; break;
    }
    log.meta.mode_label = mode_name(cfg.mode);
    log.meta.connections = cfg.connections;
    log.meta.rate = cfg.rate;
    log.meta.duration_s = static_cast<long>(cfg.duration.count());
    log.meta.interval_s = static_cast<long>(cfg.interval.count());
    log.meta.read_interval_s = static_cast<long>(cfg.read_interval.count());
    log.meta.read_len = cfg.read_len;
    log.meta.window_lower = cfg.window_lower;
    log.meta.window_upper = cfg.window_upper;
    log.meta.probe_interval_ms = cfg.probe_interval.count();
    log.meta.probe_timeout_ms =
        static_cast<long>(cfg.probe_timeout.count()) * 1000;
    log.meta.degraded_above_ms = cfg.degraded_above.count();
    if (cfg.proxy.enabled())
      log.meta.proxy = cfg.proxy.host + ":" + cfg.proxy.port;
    if (cfg.probe_proxy.enabled())
      log.meta.probe_proxy = cfg.probe_proxy.host + ":" + cfg.probe_proxy.port;
    log.meta.fail_on_status_spec = cfg.fail_on_status_spec;
    log.meta.user_agent = cfg.user_agent;
    log.meta.tool_version = kToolVersion;
    // Recorded as a count, not as the headers themselves: they routinely carry
    // bearer tokens and session cookies, and a report is a file people attach to
    // tickets and email around.
    log.meta.extra_header_count = static_cast<int>(cfg.extra_headers.size());
    log.meta.body_data_source = cfg.body_data_source;
  }

  int run() {
    std::string err;
    if (!build_setup_plan(err)) {
      std::fprintf(stderr, "Error: %s\n", err.c_str());
      return 2;
    }
    if (!addr.resolve(cfg.connect_host(), cfg.connect_port(), err)) {
      std::fprintf(stderr, "Error: cannot resolve %s (%s)\n",
                   cfg.connect_endpoint().c_str(), err.c_str());
      return 2;
    }
    fill_meta();

    reactor = Reactor::create();
    conns.resize(static_cast<std::size_t>(cfg.connections));
    for (std::size_t i = 0; i < conns.size(); ++i)
      conns[i].id = static_cast<ConnId>(i);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_sigint);

    if (cfg.probe_enabled) {
      prober.reset(new Prober(cfg, tls));
      std::string perr;
      if (!prober->start(perr)) {
        // A broken probe path costs the verdict, not the test. Say so loudly and
        // carry on rather than refusing to run at all.
        if (chatty())
          std::fprintf(stderr,
                     "Warning: availability probe disabled (%s). The test will"
                     " run, but nothing will measure whether the service stayed"
                     " up.\n",
                     perr.c_str());
        prober.reset();
      } else {
        prober->on_sample = [this](const ProbeSample& s) {
          ProbeSample marked = s;
          // Tagged here, where the config lives, so the EventLog and both
          // renderers stay free of any policy about what counts as a failure.
          marked.status_fails = cfg.fail_on_status.matches(s.status);
          log.add_probe(marked);
        };
      }
    }

    if (cfg.capacity.enabled) build_levels();

    char probe_desc[128] = "disabled (no availability measurement, no verdict)";
    if (prober) {
      std::snprintf(probe_desc, sizeof(probe_desc),
                    "every %.2gs, timeout %llds", cfg.probe_interval.count() / 1000.0,
                    static_cast<long long>(cfg.probe_timeout.count()));
    }
    if (chatty())
      std::fprintf(stderr,
                 "slowhttptest-ng: %s -> %s\n"
                 "  resolved %s to %s (%zu candidate(s))%s\n"
                 "  connections=%d rate=%d/s interval=%llds duration=%llds\n"
                 "  probe: %s\n"
                 "  (authorized testing only)\n\n",
                 attack.name(), log.meta.target_url.c_str(),
                 cfg.connect_endpoint().c_str(),
                 ResolvedAddr::describe(current_addr()).c_str(),
                 addr.candidates().size(),
                 cfg.proxy.enabled() ? " via proxy" : "", cfg.connections,
                 cfg.rate, static_cast<long long>(cfg.interval.count()),
                 static_cast<long long>(cfg.duration.count()), probe_desc);

    start = Clock::now();
    if (prober) prober->set_epoch(start);
    TimePoint next_status = start + kStatusInterval;
    TimePoint last_conn_sample = start;
    std::vector<IoEvent> events;

    // Phase 1: measure the target with no load on it. Without this the report
    // cannot tell "we broke it" from "it was already broken".
    target_conns = 0;
    phase = Phase::Baseline;
    phase_deadline =
        start + (prober ? cfg.probe_interval * (kBaselineProbes + 1) +
                              cfg.probe_timeout
                        : std::chrono::milliseconds(0));

    bool gave_up = false;
    while (!g_stop.load()) {
      TimePoint now = Clock::now();

      switch (phase) {
        case Phase::Baseline:
          if (!prober || static_cast<int>(log.probes.size()) >= kBaselineProbes ||
              now >= phase_deadline) {
            calibrate_from_baseline();
            phase = Phase::Attack;
            log.attack_start_s = elapsed(now);
            log.note(log.attack_start_s, Availability::Ok, "Attack started",
                     std::string(log.meta.mode_label) + " · " +
                         std::to_string(cfg.connections) + " connections · " +
                         std::to_string(cfg.rate) + "/s");
            if (cfg.capacity.enabled) {
              enter_level(now);
            } else {
              target_conns = cfg.connections;
              phase_deadline = now + cfg.duration;
            }
          }
          break;

        case Phase::Attack: {
          bool done = false;
          if (cfg.capacity.enabled) {
            done = !capacity_tick(now);
          } else {
            done = now >= phase_deadline;
          }
          ramp(now);
          // Fail fast instead of burning the whole duration against a target that
          // is simply not there (wrong port, nothing listening, every candidate
          // refused), or a setup chain that can never complete.
          if (ready_total == 0 &&
              connect_failed_total + setup_failed_total >= kGiveUpAfterFailures) {
            gave_up = true;
            done = true;
          }
          if (done) {
            log.attack_end_s = elapsed(now);
            log.note(log.attack_end_s, Availability::Ok, "Attack stopped",
                     gave_up ? "giving up: no connection could be established"
                             : "test duration reached");
            close_all();
            target_conns = 0;
            if (prober) {
              prober->set_active(true);
              prober->set_tag({});
            }
            phase = Phase::Recovery;
            phase_deadline = now + (prober && !gave_up ? kRecoveryWatch
                                                       : std::chrono::seconds(0));
          }
          break;
        }

        case Phase::Recovery:
          // Stop early once the service is answering normally again: the point
          // is to time the recovery, not to wait out a fixed window.
          if (now >= phase_deadline ||
              (!log.probes.empty() &&
               log.probes.back().t > log.attack_end_s &&
               log.probes.back().state == Availability::Ok)) {
            phase = Phase::Finished;
          }
          break;

        case Phase::Finished:
          break;
      }
      if (phase == Phase::Finished) break;

      if (prober) {
        prober->tick(now);
        sync_probe_registration();
      }

      TimePoint next = phase_deadline;
      if (!timers.empty()) next = std::min(next, timers.begin()->first);
      // Wait for the *same* instant the status line is actually refreshed at.
      // These two used to disagree -- the wait targeted a 250 ms grid while the
      // refresh only advanced its marker once a second -- so for three quarters
      // of every second the deadline was already in the past, poll() was handed
      // a zero timeout, and the loop spun. With many connections that turns into
      // a full core burned in the kernel rescanning every descriptor.
      next = std::min(next, next_status);
      auto timeout =
          std::chrono::duration_cast<std::chrono::milliseconds>(next - now);
      if (timeout.count() < 0) timeout = std::chrono::milliseconds(0);
      // Never sleep past the next probe deadline check.
      if (prober) timeout = std::min(timeout, std::chrono::milliseconds(100));

      events.clear();
      reactor->wait(events, timeout);

      for (const auto& ev : events) {
        if (prober && ev.fd == probe_reg_fd && ev.fd >= 0) {
          prober->on_event(Clock::now(), ev.readable, ev.writable, ev.error);
          continue;
        }
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
      if (prober) {
        prober->tick(now);
        sync_probe_registration();
      }
      if (now - last_conn_sample >= std::chrono::milliseconds(500)) {
        log.conns.push_back(
            ConnSample{elapsed(now), held_connections(), target_conns});
        last_conn_sample = now;
      }
      if (now >= next_status) {
        status_line(now);
        next_status = now + kStatusInterval;
      }
    }

    const TimePoint stop_at = Clock::now();
    if (log.attack_end_s == 0 && log.attack_start_s > 0)
      log.attack_end_s = elapsed(stop_at);
    log.run_end_s = elapsed(stop_at);
    log.conns.push_back(
        ConnSample{log.run_end_s, held_connections(), target_conns});
    close_all();
    status_line(stop_at);

    const char* why = gave_up         ? "giving up"
                      : g_stop.load() ? "interrupted"
                                      : "finished";
    if (chatty())
      std::fprintf(stderr,
                 "\n\nDone (%s). opened=%ld connected=%ld ready=%ld"
                 " peer_closed=%ld connect_failed=%ld setup_failed=%ld\n",
                 why, opened_total, connected_total, ready_total,
                 peer_closed_total, connect_failed_total, setup_failed_total);

    // Never report success for a test that never reached the target: a silent
    // exit 0 here would make CI and scripts treat an unreachable host as a pass.
    if (ready_total == 0) {
      std::fprintf(stderr,
                   "\nERROR: no usable connection was ever established to %s"
                   " (tried %zu resolved address(es)).\n"
                   "       The target may be down, firewalled, on another port,"
                   " or rejecting the TLS/proxy setup -- nothing was actually"
                   " tested.\n",
                   cfg.connect_endpoint().c_str(), addr.candidates().size());
      log.exit_code = 3;
    }
    scheme_mismatch_hint();

    if (prober) {
      const Verdict v = log.evaluate(cfg.availability_threshold);
      if (chatty()) print_verdict(stderr, v, log);
      if (cfg.report) write_reports(cfg, log, v);
    } else if (cfg.report) {
      if (chatty())
        std::fprintf(stderr,
                   "\nNo report written: reporting describes availability, and"
                   " the availability probe was disabled or unavailable.\n");
    }
    return log.exit_code;
  }
};

Engine::Engine(const Config& cfg, Attack& attack)
    : impl_(new Impl(cfg, attack)) {}
Engine::~Engine() = default;
int Engine::run() { return impl_->run(); }

}  // namespace slowhttp
