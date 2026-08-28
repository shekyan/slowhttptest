// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/engine.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
// sysctlbyname is Darwin-only, and glibc removed <sys/sysctl.h> outright in
// 2.32, so the include itself would break the Linux build.
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#include <time.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <condition_variable>
#include <cstdarg>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
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

// Ceiling on how long one maintenance sweep may spend closing connections
// before yielding back to the event loop. An event loop that does unbounded
// work in a single pass is not an event loop.
constexpr std::chrono::milliseconds kSweepBudget{50};

// The same ceiling for opening them. connect() can be slow when local ports are
// scarce, and the catch-up allowance means a late pass may have thousands of
// slots to fill.
constexpr std::chrono::milliseconds kRampBudget{20};

// How long the loop may sleep while it still has connections to open. At -r 500
// this spends the allowance about five at a time instead of five hundred. The
// classic tool sleeps 1/rate between single connects, which is smoother still,
// but it also polls that often; this keeps the wake-up rate bounded no matter
// how large -r is.
constexpr std::chrono::milliseconds kRampWake{10};

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

// Cancelling means cancelling. The handler prints one fixed line and leaves;
// it closes nothing, writes no report, and runs no cleanup.
//
// Two things are worth recording here, because this path was misdiagnosed
// repeatedly and the evidence was misleading each time.
//
// First, the handler must never be able to block. write(2) to a terminal that
// is not draining does block, and blocking here traps the process inside the
// very handler whose job is to leave -- reproduced with stderr on a pipe nobody
// reads, where the process survived SIGINT entirely. Hence the non-blocking
// stderr below: the message is best-effort, the exit is not.
//
// Second, _exit() is reached immediately after the message, so any pause the
// operator sees after that is the kernel, not this code: the process is already
// in its exit path with sockets still open. Whether that pause is avoidable is
// an open question and not one this handler can answer -- what it can do is not
// add to it, which is why it closes nothing.
//
// Two things that look like this bug but are not. A leftover zombie is a
// convincing impostor: ps lists it, its argv is gone so the name shows in
// parentheses, SIGKILL does nothing, and it dies when its parent shell does --
// lsof settles it, since no open descriptors means the process is finished. And
// a process shown by ps as state "E" is already inside kernel exit, which is why
// no profiler can attach to it and no signal will hurry it.
//
// The message is a fixed string. Nothing is formatted here: snprintf is not
// async-signal-safe, and every additional statement in a handler is another one
// that can block.
// "nothing written" used to lead this line and was read, reasonably, as nothing
// having been written to the connections. It meant no report file and no
// verdict, which is a different statement and worth making in those words.
// Says plainly that there is no faster way out, because there is not, and an
// earlier version of this message implied kill -9 was one. It is not: SIGKILL
// cannot be caught, so nothing here runs, but the kernel still closes every
// remaining descriptor in the exit path -- one at a time, paying the content
// filter's timeout on each. That is the same path a second Ctrl-C used to take,
// measured at 2h09m and 3h48m against runs that finish in about 30 s when left
// alone. It does not even return the shell any sooner: the process is not
// reaped until that teardown completes.
constexpr char kCancelMessage[] =
    "\nCancelled. No report or verdict written -- a partial run measures\n"
    "nothing worth reporting. Closing the open connections now.\n"
    "The count below will not move for the first second or so; that is\n"
    "normal, and this is the fastest way out. Ctrl-C again is ignored,\n"
    "and kill -9 is not a shortcut: it makes the OS close the remaining\n"
    "sockets one at a time, which takes far longer, and your shell waits\n"
    "for that either way.\n";

// Set by the handler, read by the event loop. sig_atomic_t and volatile are what
// make that legal: the loop must see the store, and the handler may write
// nothing more complicated.
volatile sig_atomic_t g_cancelled = 0;

void handle_cancel(int) {
  // Make stderr non-blocking before writing to it. A terminal that is not
  // draining -- scrolled back, flow-controlled, or a pipe nobody is reading --
  // makes write(2) block, and blocking here traps the process inside the very
  // handler whose job is to leave. The message is best-effort; the exit is not.
  //
  // fcntl and write are async-signal-safe, so this is legitimate in a handler.
  // Restoring the flag afterwards would be pointless: the next statement exits.
  const int flags = ::fcntl(2, F_GETFL, 0);
  if (flags != -1) ::fcntl(2, F_SETFL, flags | O_NONBLOCK);
  ssize_t ignored = ::write(2, kCancelMessage, sizeof(kCancelMessage) - 1);
  (void)ignored;
  // Deliberately not _exit(). This used to leave immediately on the theory that
  // the kernel closes the descriptors anyway, so doing it here only delayed the
  // inevitable. That is wrong, and expensively so: the kernel's exit path closes
  // them one at a time, and each close of a filter-held socket waits up to a
  // second. Cancelling a run holding 3000 connections that way took 2h09m, and
  // once the process is inside exit no further signal can reach it -- which is
  // why pressing Ctrl-C again appeared to do nothing.
  //
  // So the loop is told to stop and closes them through the closer pool
  // instead, which does the same work N at a time. All this handler does is
  // set the flag.
  ++g_cancelled;
}

// SA_RESETHAND and SA_NODEFER together mean that even if the write above blocks
// -- a terminal that is not draining will do it -- a second Ctrl-C still gets
// through to the default disposition and kills the process. Without SA_NODEFER
// the signal would merely go pending while the handler sat there, which is
// exactly how an earlier version of this made itself unkillable.
//
// That second Ctrl-C is an escape hatch, not a speed-up: it kills the process
// mid-teardown and hands the remaining descriptors back to the kernel, which
// closes them one at a time. The message says so.
void install_cancel_handler() {
  struct sigaction sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_cancel;
  sigemptyset(&sa.sa_mask);
  // Deliberately no SA_RESETHAND. It used to be here so a second Ctrl-C would
  // reach the default disposition and kill the process outright, which sounds
  // like the right escape hatch and is in fact the worst available outcome:
  // killing mid-teardown hands every remaining descriptor to the kernel, which
  // closes them one at a time. Measured on the same run: about a minute if left
  // alone, 3h48m after a second Ctrl-C. There is no fast way out of a process
  // holding thousands of filter-held sockets, so the handler stays installed and
  // repeated interrupts are absorbed and explained. SIGKILL from another
  // terminal is still available to anyone who insists, at the same cost.
  sa.sa_flags = SA_NODEFER;
  ::sigaction(SIGINT, &sa, nullptr);
  ::sigaction(SIGTERM, &sa, nullptr);
}

// How many content filters the OS reports as active, or -1 where it does not
// say. A filter intercepts sockets between send() and the wire, which shows up
// as connections that carry no traffic and as a per-socket wait on close.
long active_content_filters() {
#if defined(__APPLE__)
  int value = 0;
  std::size_t len = sizeof(value);
  if (::sysctlbyname("net.cfil.active_count", &value, &len, nullptr, 0) != 0)
    return -1;
  return value;
#else
  return -1;
#endif
}

// Closes descriptors on other threads, so the event loop never blocks on one.
//
// This is not an optimisation. close(2) on a socket held by a macOS content
// filter blocks in cfil_sock_close_wait() for up to net.cfil.close_wait_timeout
// -- 1000 ms, measured here to three decimal places -- and the engine closes
// connections from inside its event loop: on error events, on connect timeouts,
// and when the peer-closed sweep finds a dead connection. Each one froze the
// loop for a second. Observed against a real target: a run asked for -l 20 that
// executed for 1080 seconds, because roughly a thousand blocking closes landed
// during it. A run that ignores its own duration reports a test that never
// happened.
//
// Bounding the work per pass cannot fix it -- the budget is checked before a
// close, so a single one still overshoots by a full second. The only fix is to
// stop doing it on this thread.
//
// The threads touch nothing but the descriptors handed to them. All engine
// bookkeeping stays on the event loop.
class Closer {
 public:
  explicit Closer(unsigned threads) {
    for (unsigned i = 0; i < threads; ++i)
      workers_.emplace_back([this] { run(); });
  }

  ~Closer() {
    {
      std::lock_guard<std::mutex> lk(m_);
      stop_ = true;
    }
    cv_.notify_all();
    for (auto& t : workers_) if (t.joinable()) t.join();
  }

  void submit(int fd) {
    if (fd < 0) return;
    {
      std::lock_guard<std::mutex> lk(m_);
      queue_.push_back(fd);
      ++pending_;
    }
    cv_.notify_one();
  }

  long pending() const {
    std::lock_guard<std::mutex> lk(m_);
    return pending_;
  }

  // Waits until every submitted descriptor is closed, calling `tick` about once
  // a second so a long wait can report progress rather than look like a hang.
  template <typename F>
  void drain(F tick) {
    std::unique_lock<std::mutex> lk(m_);
    bool told = false;
    while (pending_ > 0) {
      // Report before the first wait, not after it. A teardown that sits silent
      // even for a second reads as a hang, and the operator's remedy for a hang
      // -- another Ctrl-C -- is the one action that makes this slower.
      if (!told) {
        const long left = pending_;
        lk.unlock();
        tick(left);
        lk.lock();
        told = true;
        continue;
      }
      if (idle_.wait_for(lk, std::chrono::milliseconds(250)) ==
          std::cv_status::timeout) {
        const long left = pending_;
        lk.unlock();
        tick(left);
        lk.lock();
      }
    }
  }

 private:
  void run() {
    for (;;) {
      int fd = -1;
      {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [this] { return stop_ || !queue_.empty(); });
        if (queue_.empty()) return;  // stopping, nothing left
        fd = queue_.front();
        queue_.pop_front();
      }
      ::close(fd);
      {
        std::lock_guard<std::mutex> lk(m_);
        --pending_;
      }
      idle_.notify_all();
    }
  }

  mutable std::mutex m_;
  std::condition_variable cv_;
  std::condition_variable idle_;
  std::deque<int> queue_;
  std::vector<std::thread> workers_;
  long pending_ = 0;
  bool stop_ = false;
};

// Enough to hide a one-second stall behind ongoing work without turning
// teardown into a thundering herd. Teardown of n connections costs about
// n/threads seconds in the worst case where every close blocks.

// Ceiling on descriptors waiting to be closed. Handing a descriptor to the
// closer returns immediately, so without a bound a run that churns connections
// faster than they close would accumulate open descriptors and eventually fail
// with EMFILE -- reported as a local limit, which is true but avoidable.
//
// Kept small deliberately. It is added to the descriptor reserve below, and on
// Darwin that total has to stay under OPEN_MAX (10240) at the largest usable
// -c: an earlier attempt used 256 and pushed -c 10000 past the ceiling, which
// silently changed which error a descriptor-starved run reported.
// Teardown costs about connections/threads seconds when every close blocks for
// the filter's full timeout, so the pool is sized to the run. Threads waiting on
// a condition variable or inside close(2) cost nothing but stack.
unsigned closer_threads(int connections) {
  // Teardown takes about connections/threads seconds when every close waits out
  // the filter's full timeout, so the pool has to be large enough that the wait
  // is one a person will sit through. At -c 5000 this is 256 threads and about
  // 15 seconds; with 64 it was a minute, and a minute of apparently frozen
  // output is long enough that the operator kills the process -- which hands
  // every remaining descriptor to the kernel's serial close and turns a minute
  // into hours. Threads parked on a condition variable or blocked in close(2)
  // cost stack and nothing else.
  const unsigned want = static_cast<unsigned>(connections / 16);
  return want < 8u ? 8u : (want > 256u ? 256u : want);
}
constexpr long kMaxPendingCloses = 64;

// Colour, but only onto a terminal.
//
// The classic tool emits escapes unconditionally, which is why its output is
// unreadable in a file and why parsing its own numbers back out needs the codes
// stripped first -- a pattern that skips non-digits lands on the 1 in "[1;32m"
// and reports that as the value. Asking isatty costs nothing and keeps captured
// output plain.
bool use_colour() {
  static const bool yes = ::isatty(2) == 1;
  return yes;
}
const char* C(const char* code) { return use_colour() ? code : ""; }

// The classic tool's palette, same names, so the two look alike side by side.
constexpr const char* kBlue = "\x1b[0;34m";
constexpr const char* kLBlue = "\x1b[1;34m";
constexpr const char* kGreen = "\x1b[0;32m";
constexpr const char* kLGreen = "\x1b[1;32m";
constexpr const char* kLRed = "\x1b[1;31m";
constexpr const char* kReset = "\x1b[0m";

// Wall-clock stamp in the classic tool's format, e.g. "Thu Aug 13 12:30:12
// 2026". ctime_r rather than ctime for thread safety, and the trailing newline
// it appends has to come off.
std::string stamp_now() {
  const time_t now = ::time(nullptr);
  char buf[32] = {0};
  if (::ctime_r(&now, buf) == nullptr) return "";
  std::string out(buf);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
    out.pop_back();
  return out;
}

// The classic tool's exit statuses, same words, so the two agree on what
// happened. Anything this engine can end in maps onto one of them.
enum class ExitStatus {
  TimeLimit,        // "Hit test time limit"
  AllClosed,        // "No open connections left"
  CannotConnect,    // "Cannot establish connection"
  ConnectionRefused,
  Cancelled,
  Unexpected
};

// 1st, 2nd, 3rd, 4th. The classic tool prints "%dth" unconditionally and so
// says "3th second"; that is a wording bug rather than a format worth matching,
// and both places in this tool use the same helper so they cannot disagree.
const char* ordinal_suffix(long n) {
  const long tens = n % 100;
  if (tens >= 11 && tens <= 13) return "th";
  switch (n % 10) {
    case 1:  return "st";
    case 2:  return "nd";
    case 3:  return "rd";
    default: return "th";
  }
}

const char* exit_status_text(ExitStatus e) {
  switch (e) {
    case ExitStatus::TimeLimit:         return "Hit test time limit";
    case ExitStatus::AllClosed:         return "No open connections left";
    case ExitStatus::CannotConnect:     return "Cannot establish connection";
    case ExitStatus::ConnectionRefused: return "Connection refused";
    case ExitStatus::Cancelled:         return "Cancelled by user";
    case ExitStatus::Unexpected:
    default:                            return "Unexpected error";
  }
}

// Who a failed connect actually implicates. The distinction is the whole point:
// a tool that reports "the target may be down" when the operator simply ran out
// of file descriptors sends them to debug the wrong machine.
enum class Blame { Local, Target, Unknown };

Blame blame_for(int err) {
  switch (err) {
    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
    case EADDRNOTAVAIL:
    case EADDRINUSE:
      return Blame::Local;
    case ECONNREFUSED:
    case ETIMEDOUT:
    case EHOSTUNREACH:
    case ENETUNREACH:
    case ENETDOWN:
    case ECONNRESET:
      return Blame::Target;
    default:
      return Blame::Unknown;
  }
}

// What to do about it, not just what it was.
std::string advice_for(int err) {
  switch (err) {
    case EMFILE:
    case ENFILE:
      return "this process is out of file descriptors. That is a limit on this"
             " machine, not a property of the target -- raise it with"
             " 'ulimit -n' and re-run.";
    case EADDRNOTAVAIL:
    case EADDRINUSE:
      return "the local ephemeral port range is exhausted. One connection needs"
             " one local port per destination, and sockets in TIME_WAIT still"
             " hold theirs -- lower -c, or wait for them to drain.";
    case ENOBUFS:
    case ENOMEM:
      return "the kernel is out of socket buffer memory locally. Lower -c.";
    case ECONNREFUSED:
      return "the target actively refused the connection -- nothing is listening"
             " on that port.";
    case ETIMEDOUT:
      return "the connection attempt timed out. The port is likely filtered by a"
             " firewall rather than closed.";
    case EHOSTUNREACH:
    case ENETUNREACH:
    case ENETDOWN:
      return "the target is not reachable from this host -- a routing or network"
             " problem rather than a busy server.";
    case ECONNRESET:
      return "the target reset the connection during setup.";
    default:
      return {};
  }
}

// Raises the descriptor limit to what the run needs, as far as the hard limit
// allows. Doing it here beats telling the operator to do it: the soft limit is
// commonly 256 on macOS while the hard limit is enormous, so the fix is
// mechanical and there is no reason to make a human perform it.
bool ensure_descriptor_limit(int wanted, std::string& error) {
  rlimit rl{};
  if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return true;  // can't tell; proceed

  if (rl.rlim_cur != RLIM_INFINITY &&
      rl.rlim_cur < static_cast<rlim_t>(wanted)) {
    rlimit want = rl;
    want.rlim_cur = (rl.rlim_max == RLIM_INFINITY)
                        ? static_cast<rlim_t>(wanted)
                        : std::min(static_cast<rlim_t>(wanted), rl.rlim_max);
    if (::setrlimit(RLIMIT_NOFILE, &want) != 0 ||
        want.rlim_cur < static_cast<rlim_t>(wanted)) {
      char buf[320];
      std::snprintf(buf, sizeof(buf),
                    "this run needs %d file descriptors but the limit is %llu"
                    " (hard limit %llu). Raise it with 'ulimit -n %d', or lower"
                    " -c.",
                    wanted, static_cast<unsigned long long>(rl.rlim_cur),
                    static_cast<unsigned long long>(rl.rlim_max), wanted);
      error = buf;
      return false;
    }
  }
  return true;
}

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
  // When this slot started dialling, for the connect timeout.
  TimePoint opened_at{};
  // Counted against the in-flight ceiling; cleared when it becomes usable or
  // closes. A flag rather than a recount, since ramp() consults this every
  // pass through the loop and rescanning every slot there would be O(n) per wake.
  bool in_flight = false;
  // What the setup chain (proxy CONNECT / TLS handshake) is waiting for.
  unsigned setup_want = 0;
  // Bytes this engine has successfully written to the socket, which is not the
  // same as bytes that reached the network. Against a filtered path the two
  // diverge: send() returns success into the filter's queue while the kernel
  // reports tcpi_txbytes == 0 for the life of the connection. Comparing them is
  // how a connection that carried no load at all gets noticed instead of being
  // counted as held.
  long sent_bytes = 0;
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
  std::unique_ptr<Closer> closer;
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
  long connect_timeout_total = 0;  // dropped by --connect-timeout
  int in_flight_conns = 0;         // opened but not yet past setup

  // Capacity staircase state.
  std::size_t level_idx = 0;
  std::vector<int> levels;
  bool level_measuring = false;
  std::size_t level_probe_begin = 0;
  TimePoint level_started{};
  // What the current level actually achieved, as against what it asked for.
  bool level_ramped = false;
  int level_max_active = 0;
  int level_min_active = 0;

  // Connections that are up and carrying the attack, which is not the same as
  // active_conns: that counts a slot from the moment the socket is opened and
  // handed to the reactor, so it includes sockets still in connect(), the proxy
  // CONNECT exchange, or the TLS handshake. Occupancy has to mean established,
  // or a level "reaches" a target using sockets sitting in the peer's accept
  // backlog -- measured doing exactly that against a server with listen(8).
  int established_conns() const {
    const int n = active_conns - in_flight_conns;
    return n > 0 ? n : 0;
  }

  // Index of the resolved address we are currently dialing. While nothing has
  // ever connected we rotate through the candidates so an IPv6-first "localhost"
  // still reaches an IPv4-only listener; once one works we pin to it.
  std::size_t cand_idx = 0;
  bool address_pinned = false;
  bool logged_window_ = false;
  bool logged_tls_ = false;
  std::uint64_t bytes_read_total = 0;
  std::string last_setup_error_;  // kept for the scheme-mismatch hint
  std::map<int, long> connect_errnos_;  // errno -> times seen

  Impl(const Config& c, Attack& a) : cfg(c), attack(a) {}

  double elapsed(TimePoint t) const {
    return std::chrono::duration<double>(t - start).count();
  }

  // Progress and summary output. At -q / -v 0 the run is silent on stdout and
  // stderr and speaks only through its exit code and any report files. Genuine
  // errors are deliberately NOT gated on this: a silent non-zero exit tells the
  // operator nothing about what went wrong.
  bool chatty() const { return cfg.log_level >= 1; }

  // -v levels mean what they mean in the classic tool: 0 fatal, 1 info,
  // 2 error, 3 warn, 4 debug. Before this, only 1 and 4 did anything at all --
  // 2 and 3 produced output identical to 1, so the flag looked like it had five
  // settings and had three.
  //
  // Anything above info also switches the status display from the redrawn block
  // to one appended line per update. The two cannot share a terminal: the block
  // repaints over its own lines, so a per-connection trace printed into it is
  // overwritten a moment later. Verbose output is a log, not a dashboard.
  bool verbose_log() const { return cfg.log_level >= 2; }

  // Stamped like the classic tool's, which prefixes every line, so two runs can
  // be read side by side.
  void trace(int level, const char* fmt, ...) const {
    if (cfg.log_level < level) return;
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    char clock[16] = {0};
    const time_t wall = ::time(nullptr);
    struct tm tmv;
    if (::localtime_r(&wall, &tmv) != nullptr)
      std::strftime(clock, sizeof(clock), "%H:%M:%S", &tmv);
    static const char* const kTag[] = {"", "info", "error", "warn", "debug"};
    std::fprintf(stderr, "%s %-5s %s\n", clock,
                 kTag[level < 5 ? level : 4], msg);
  }

  const addrinfo* current_addr() const { return addr.candidates()[cand_idx]; }

  void note_connect_success() {
    ++connected_total;
    address_pinned = true;
  }

  // `err` is errno from the failed call, or 0 when the reason is unknown.
  void note_connect_failure(int err) {
    trace(2, "connect failed: %s", err ? std::strerror(err) : "unknown");
    ++connect_failed_total;
    if (err != 0) {
      auto& count = connect_errnos_[err];
      ++count;
      // Say it once per distinct cause, the first time it happens. Repeating it
      // ten thousand times would bury the status line, and staying silent is
      // what made a local descriptor limit look like a dead target.
      if (count == 1 && chatty()) {
        const std::string advice = advice_for(err);
        interrupt_status();
        std::fprintf(stderr, "\n  connect failed (%s)%s%s\n", std::strerror(err),
                     advice.empty() ? "" : ": ", advice.c_str());
      }
    }
    if (address_pinned) return;
    const auto& cands = addr.candidates();
    if (cands.size() > 1) cand_idx = (cand_idx + 1) % cands.size();
  }

  // The errno responsible for most connect failures, or 0 if none were recorded.
  int dominant_connect_errno() const {
    int worst = 0;
    long best = 0;
    for (const auto& kv : connect_errnos_) {
      if (kv.second > best) {
        best = kv.second;
        worst = kv.first;
      }
    }
    return worst;
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
    c.sent_bytes = 0;
    c.setup_want = 0;
    c.opened_at = Clock::now();
    const ConnOptions opts = attack.conn_options(c.id);
    if (!c.sock.start_connect(current_addr(), opts.recv_buffer, plan)) {
      note_connect_failure(c.sock.connect_errno());
      return;  // retry on a later ramp tick, possibly on the next candidate
    }
    if (opts.recv_buffer > 0 && !logged_window_) {
      logged_window_ = true;
      interrupt_status();
      log.meta.kernel_rcvbuf = c.sock.recv_buffer_size();
      // Report what the kernel actually granted: it clamps to its own floor and
      // typically reports double the request, so the effective window is bigger
      // than asked. Silently pretending otherwise would misrepresent the test.
      if (chatty())
        std::fprintf(stderr,
                   "  advertised window: requested %d B, kernel SO_RCVBUF %d B\n",
                   opts.recv_buffer, c.sock.recv_buffer_size());
    }
    if (!c.sock.ready()) {
      c.in_flight = true;
      ++in_flight_conns;
    }
    trace(4, "conn %d: socket %d -> %s", c.id, c.sock.fd(),
          ResolvedAddr::describe(current_addr()).c_str());
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

  // Split so teardown can be attributed. Closing 1500 established remote sockets
  // has been measured at 168 s here, most of it concentrated in a few hundred of
  // them, and "close_slot is slow" is not a diagnosis: the descriptor work, the
  // reactor bookkeeping and the close(2) itself are three different suspects.
  double close_syscall_s = 0;
  double close_bookkeep_s = 0;

  void close_slot(Conn& c) {
    if (!c.active) return;
    const TimePoint t0 = Clock::now();
    cancel_timer(c);
    if (c.sock.fd() >= 0) {
      reactor->remove(c.sock.fd());
      fd_to_id.erase(c.sock.fd());
    }
    const TimePoint t1 = Clock::now();
    // Handed off rather than closed here: see Closer. This call must not block,
    // because every caller of close_slot is on the event loop.
    trace(4, "conn %d: closing socket %d", c.id, c.sock.fd());
    closer->submit(c.sock.release_fd());
    const TimePoint t2 = Clock::now();
    close_bookkeep_s += std::chrono::duration<double>(t1 - t0).count();
    close_syscall_s += std::chrono::duration<double>(t2 - t1).count();
    if (c.in_flight) {
      c.in_flight = false;
      --in_flight_conns;
    }
    c.active = false;
    c.outbuf.clear();
    c.outpos = 0;
    --active_conns;
    attack.on_close(c.id);
  }

  // Closes everything still open, reporting progress.
  //
  // The progress line is not decoration. Closing thousands of established remote
  // sockets has been slow enough here to look like a hang, and a frozen status
  // line is indistinguishable from one. Bounding the loop would not make it
  // faster; saying what it is doing costs nothing.
  int close_all() {
    int remaining = 0;
    for (const auto& c : conns)
      if (c.active) ++remaining;
    if (remaining == 0) return 0;

    // Nothing is reported from here. These descriptors are queued, not closed,
    // and the caller reports the truth once the pool has actually finished.
    const bool worth_reporting = false;
    TimePoint next_note = Clock::now() + std::chrono::seconds(1);
    int closed = 0;
    // Where the time falls across the sweep, not just how much of it there is.
    // Observed by hand: the first ~1200 of 1500 closed instantly and the rest
    // crawled, which is a different fault from a uniform per-socket cost and
    // rules out the obvious O(n^2) explanations. Quarters are enough resolution
    // to tell those two shapes apart without turning this into a profiler.
    double quarter_s[4] = {0, 0, 0, 0};
    int slow_closes = 0;      // individual closes over 10 ms
    double slowest_close = 0;
    // TCP state, sampled before the close and tallied after, split by whether
    // that close turned out to be slow. If the expensive ones are all sitting in
    // one state the answer is in the connection; if they are spread across every
    // state it is not, and the cost is coming from somewhere outside TCP.
    std::map<int, long> slow_states, fast_states;
    // Slow read's entire purpose is to leave the receive buffer full, so the
    // obvious guess is that the full ones are what cost time to close. Measured,
    // it is the reverse: the expensive closes averaged zero bytes unread and the
    // free ones a couple of thousand. The costly connections are the ones that
    // never carried traffic at all.
    long slow_unread = 0, fast_unread = 0;
    std::vector<std::string> slow_diag;
    std::string one_fast_diag;
    TimePoint mark = Clock::now();
    for (auto& c : conns) {
      if (!c.active) continue;
      const int state = c.sock.tcp_state();
      const long unread = c.sock.unread_bytes();
      // The kernel's own view, kept only long enough to print. Everything
      // cheaper than asking it has already been ruled out.
      std::string diag;
      if (cfg.log_level >= 4) {
        char mine[64];
        std::snprintf(mine, sizeof(mine), "ng_sent=%ld ng_queued=%zu ",
                      c.sent_bytes, c.outbuf.size() - c.outpos);
        diag = std::string(mine) + c.sock.tcp_diag();
      }
      const double before = close_syscall_s;
      close_slot(c);
      const double took = close_syscall_s - before;
      if (took > 0.010) {
        ++slow_closes;
        ++slow_states[state];
        if (unread > 0) slow_unread += unread;
        if (slow_diag.size() < 8 && !diag.empty()) {
          char pfx[32];
          std::snprintf(pfx, sizeof(pfx), "took %6.3fs  ", took);
          slow_diag.push_back(std::string(pfx) + diag);
        }
      } else {
        ++fast_states[state];
        if (unread > 0) fast_unread += unread;
        if (one_fast_diag.empty()) one_fast_diag = diag;
      }
      if (took > slowest_close) slowest_close = took;
      const int q = std::min(3, closed * 4 / remaining);
      const TimePoint now = Clock::now();
      quarter_s[q] += std::chrono::duration<double>(now - mark).count();
      mark = now;
      ++closed;
      if (worth_reporting && now >= next_note) {
        std::fprintf(stderr, "\r  closing connections: %d/%d   ", closed,
                     remaining);
        std::fflush(stderr);
        next_note = now + std::chrono::seconds(1);
      }
    }
    if (worth_reporting)
      std::fprintf(stderr, "\r  closed %d connections%20s\n", closed, "");
    // The breakdown is for diagnosing a slow teardown, which is a question
    // about the machine and its network rather than about the run, so it stays
    // at -v 4. It earned its keep: it showed the cost was entirely in close(2)
    // and not in this engine's bookkeeping, and that the expensive closes were
    // a handful of one-second stalls rather than a per-socket price.
    if (cfg.log_level >= 4) {
      std::fprintf(stderr,
                   "  by quarter: %.2fs %.2fs %.2fs %.2fs"
                   "   (%d close(2) over 10ms, slowest %.0f ms)\n",
                   quarter_s[0], quarter_s[1], quarter_s[2], quarter_s[3],
                   slow_closes, slowest_close * 1000.0);
      auto dump_states = [](const char* label, const std::map<int, long>& m) {
        if (m.empty()) return;
        std::fprintf(stderr, "  %s by tcp state:", label);
        for (const auto& kv : m)
          std::fprintf(stderr, " %d=%ld", kv.first, kv.second);
        std::fputc('\n', stderr);
      };
      dump_states("slow", slow_states);
      dump_states("fast", fast_states);
      if (!one_fast_diag.empty())
        std::fprintf(stderr, "  fast close:  %s\n", one_fast_diag.c_str());
      for (const auto& d : slow_diag)
        std::fprintf(stderr, "  SLOW close:  %s\n", d.c_str());
      const int fast_closes = closed - slow_closes;
      std::fprintf(stderr,
                   "  unread bytes at close: slow avg %ld, fast avg %ld\n",
                   slow_closes ? slow_unread / slow_closes : 0,
                   fast_closes ? fast_unread / fast_closes : 0);
    }
    return closed;
  }

  void flush(Conn& c) {
    while (c.outpos < c.outbuf.size()) {
      long n = c.sock.send_some(c.outbuf.data() + c.outpos,
                                c.outbuf.size() - c.outpos);
      if (n > 0) {
        trace(4, "conn %d: socket %d wrote %ld byte(s)", c.id, c.sock.fd(), n);
        c.outpos += static_cast<std::size_t>(n);
        c.sent_bytes += n;
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
    if (c.in_flight) {
      c.in_flight = false;
      --in_flight_conns;
    }
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
              interrupt_status(),
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
        note_connect_failure(c.sock.connect_errno());
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
    // Drain what is buffered, but not without limit.
    //
    // Only rapid reset reaches this loop more than once. Every other attack
    // either does not ask for read events at all, or closes the connection on
    // the first response -- so `if (!c.active) return` ends it after a single
    // recv. Rapid reset reads and discards on purpose, which lets a peer that
    // keeps refilling the socket keep this loop running.
    //
    // Measured against a peer blasting continuously over loopback: 917
    // iterations, 3.7 MB and 4.9 ms in one dispatch. That is 5% of rapid
    // reset's 100 ms tick and never disturbed the 1 s status cadence, so this
    // is a bound on a tail rather than a repair for observed starvation. The
    // tail is worth bounding anyway: how long it runs is decided by the peer's
    // throughput and the kernel's receive buffer, neither of which this tool
    // picks, and everything sharing this thread -- probe deadlines, the ramp,
    // attack timers -- waits behind it.
    //
    // Returning early loses nothing. Both reactors are level-triggered (the
    // kqueue backend registers without EV_CLEAR), so a socket with bytes still
    // pending is reported again on the very next wakeup, with the timers
    // serviced in between.
    constexpr int kMaxReadOpsPerDispatch = 64;
    constexpr std::uint64_t kMaxReadBytesPerDispatch = 256 * 1024;

    char buf[4096];
    int ops = 0;
    std::uint64_t drained = 0;
    for (;;) {
      if (++ops > kMaxReadOpsPerDispatch || drained >= kMaxReadBytesPerDispatch)
        return;
      long n = c.sock.recv_some(buf, sizeof(buf));
      if (n > 0) {
        drained += static_cast<std::uint64_t>(n);
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

  // Opens connections toward the target, bounded by a time budget.
  //
  // Returns true if it stopped on the budget with slots still to open, so the
  // caller knows to come straight back rather than sleeping.
  //
  // The budget is not a nicety. The catch-up allowance grows with elapsed time,
  // so late in a run a single pass could try to open thousands of sockets, and
  // connect() is not always cheap: with the local ephemeral range heavily
  // occupied the kernel scans for a free port, and each call costs tens of
  // milliseconds. Measured against a real target, one unbounded pass wedged the
  // loop for 25 seconds -- the status line jumped straight from 11 s to 36 s,
  // and a profile put every sample inside start_connect.
  //
  // Bounding the pass does not slow the ramp down. The work still happens, just
  // interleaved with servicing events and printing progress, which is the whole
  // point of an event loop.
  bool ramp(TimePoint now) {
    if (target_conns <= 0) return false;
    long elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
    // Strictly `rate` per elapsed second, with no initial burst.
    //
    // There used to be an allowance of `cfg.rate` at t=0, which meant -r 500
    // opened 500 connections in one pass and 1000 within the first second. That
    // is not what -r documents, and it is not what the classic tool does: it
    // opens one at a time with usleep(1/rate) between them. Against a target
    // behind a stateful path the burst is visibly worse -- 86 to 135 SYNs still
    // unanswered at the end of a run where the classic had 0 to 2 pending.
    //
    // The leading 1 is what lets the first connection go immediately. Without
    // it a run opens nothing until a full 1/rate has elapsed, which at -r 1 is a
    // dead first second and at -r 1 -l 1 is a run that never connects at all.
    // The classic tool opens one, then sleeps 1/rate; this is the same shape.
    long allowance = 1 + (elapsed_ms * cfg.rate) / 1000;
    const TimePoint deadline = now + kRampBudget;
    for (auto& c : conns) {
      if (active_conns >= target_conns) return false;
      if (opened_total >= allowance) return false;
      // Hold back when too many are already mid-handshake. Against a target
      // that accepts normally this never triggers; against one that answers no
      // SYNs it stops the pile growing without bound, which is where holding
      // half-open sockets gets expensive.
      if (cfg.max_connecting > 0 && in_flight_conns >= cfg.max_connecting)
        return false;
      // Descriptors queued for closing are still open. Opening more while the
      // closer is behind trades a bounded wait for EMFILE. Returning false
      // rather than true yields to the event loop instead of spinning.
      if (closer && closer->pending() >= kMaxPendingCloses) return false;
      if (Clock::now() >= deadline) return true;  // more to open, yield first
      if (!c.active) open_slot(c);
    }
    return false;
  }

  // Drops connections that never finished connecting, so the slot can be reused.
  //
  // Without this the OS decides, and it is very patient: macOS retries a SYN for
  // 75 seconds. Against a target that drops SYNs -- a rate limiter, a full
  // backlog -- every slot silently fills with connections that will never
  // establish, the attack quietly stops applying pressure, and the status line
  // shows a large "connecting" count that never resolves. Recycling the slot
  // sends a fresh SYN instead, which is both more honest and more effective.
  void reap_stalled(TimePoint now) {
    const bool check_timeout = cfg.connect_timeout.count() > 0;
    // Only slow read needs asking. Every other mode watches for readability, so
    // a peer's FIN arrives as an ordinary readable event and is handled there.
    const bool check_peer_closed = !attack.wants_read_events();
    if (!check_timeout && !check_peer_closed) return;

    // Closing is not free -- a single close() has been measured blocking for
    // milliseconds against an unresponsive peer -- and this sweep can have
    // thousands of candidates at once. Doing them all in one pass stalls the
    // event loop for as long as that takes: observed as the status line jumping
    // from 10 s straight to 35 s, with a profile showing every sample inside
    // close(). Whatever is left is picked up on the next sweep.
    const TimePoint sweep_deadline = now + kSweepBudget;

    for (auto& c : conns) {
      if (!c.active) continue;
      if (Clock::now() >= sweep_deadline) break;

      if (!c.sock.ready()) {
        if (check_timeout && now - c.opened_at >= cfg.connect_timeout) {
          ++connect_timeout_total;
          trace(3, "conn %d: handshake stalled past %llds, reclaiming the slot",
                c.id, (long long)cfg.connect_timeout.count());
          // Recorded as a timeout so it lands in the by-cause breakdown
          // alongside real connect failures rather than vanishing.
          note_connect_failure(ETIMEDOUT);
          close_slot(c);
        }
        continue;
      }

      // An established connection whose peer has closed is holding nothing.
      // Counting it as held overstates the attack -- observed in the field at
      // 5740 of a reported 10000 -- and leaving it open wastes the slot that
      // could carry a live connection instead.
      if (check_peer_closed && c.sock.peer_has_closed()) {
        trace(3, "conn %d: peer closed, connection is holding nothing", c.id);
        ++peer_closed_total;
        close_slot(c);
      }
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
    level_ramped = false;
    level_max_active = 0;
    level_min_active = 0;
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
    lvl.ramped = level_ramped;
    lvl.reached_max = level_max_active;
    lvl.reached_min = level_min_active;
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

    // A level that never reached its target says nothing about that target, in
    // either direction. "held" would be the more dangerous of the two mistakes
    // -- it reads as a server that coped with a load it was never given.
    if (!lvl.ramped) {
      lvl.inconclusive = true;
      lvl.denied = false;
    }
    log.capacity.push_back(lvl);

    if (chatty()) {
      interrupt_status();
      if (lvl.inconclusive)
        std::fprintf(stderr,
                     "\n  level %d: INCONCLUSIVE -- only %d connection(s) were"
                     " ever up, so the %d/%d probes served describe that load,"
                     " not %d\n",
                     lvl.connections, lvl.reached_max, lvl.probes_served,
                     lvl.probes_total, lvl.connections);
      else
        std::fprintf(stderr,
                     "\n  level %d: %d/%d probes served, median %ld ms,"
                     " occupancy %d-%d -> %s\n",
                     lvl.connections, lvl.probes_served, lvl.probes_total,
                     lvl.median_ms, lvl.reached_min, lvl.reached_max,
                     lvl.denied ? "DENIED" : "held");
    }
    if (lvl.inconclusive) {
      // Degraded rather than Ok: the timeline should not show a reassuring
      // green band for a stretch that measured nothing.
      log.note(elapsed(now), Availability::Degraded, "Level inconclusive",
               "asked for " + std::to_string(lvl.connections) +
                   " connections, never had more than " +
                   std::to_string(lvl.reached_max));
    } else {
      log.note(elapsed(now), lvl.denied ? Availability::Denied : Availability::Ok,
               lvl.denied ? "Level denied" : "Level held",
               std::to_string(lvl.probes_served) + "/" +
                   std::to_string(lvl.probes_total) + " probes served at " +
                   std::to_string(lvl.connections) + " connections (occupancy " +
                   std::to_string(lvl.reached_min) + "-" +
                   std::to_string(lvl.reached_max) + ")");
    }
  }

  // Returns false when the staircase is over.
  bool capacity_tick(TimePoint now) {
    if (!level_measuring) {
      const bool ramped = established_conns() >= target_conns;
      if (!ramped && now < phase_deadline) return true;
      // Remember whether the ramp actually finished. Measuring anyway is the
      // right call -- the probes are real and the operator wants to see them --
      // but the level cannot then be labelled with a number it never reached.
      level_ramped = ramped;
      level_measuring = true;
      level_max_active = established_conns();
      level_min_active = established_conns();
      level_probe_begin = log.probes.size();
      if (prober) prober->set_active(true);
      phase_deadline = now + cfg.capacity.hold;
      return true;
    }
    // Occupancy is sampled across the whole hold, not just at its edges: a
    // level that reaches its target and then drains has probes describing a
    // load that was no longer there.
    const int occupancy = established_conns();
    if (occupancy > level_max_active) level_max_active = occupancy;
    if (occupancy < level_min_active) level_min_active = occupancy;
    if (now < phase_deadline) return true;
    // Let an in-flight probe land before closing the books: it was launched
    // under this level's load, so counting it against the next one would both
    // understate this level and contaminate the next. The prober's own timeout
    // bounds the wait.
    if (prober && prober->busy()) return true;

    finish_level(now);
    // A level that could not be populated ends the search. Climbing to a higher
    // target when this one was already out of reach cannot produce a level that
    // ramps, so every level above would be inconclusive too -- and printing a
    // staircase of them would look like a measurement.
    if (log.capacity.back().inconclusive) return false;
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

  // The live census, in the classic tool's shape: one counter per line, redrawn
  // in place. Its labels map onto this engine's states almost exactly --
  // initializing is setup, pending is mid-handshake, connected is holding --
  // so the same numbers people already read mean the same things here.
  //
  // Redrawn by moving the cursor up rather than clearing the screen. The classic
  // clears, which wipes the banner and any warning printed before it; several
  // times this session that destroyed output that mattered. Off a terminal it
  // degrades to one plain line per update, so a captured log stays readable
  // instead of filling with escape sequences.
  int status_lines_ = 0;

  // Call before printing anything else while the run is live. The status block
  // is redrawn by moving the cursor up over its own lines; a message printed
  // into the middle of it would be overwritten on the next tick, and the count
  // would be wrong from then on. Forgetting this does not crash anything, it
  // quietly eats the message -- which is the kind of bug that hides a warning
  // precisely when it matters.
  void interrupt_status() {
    if (status_lines_ > 0) {
      std::fputc('\n', stderr);
      status_lines_ = 0;
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
    const long secs =
        std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
    const char* phase_name = phase == Phase::Baseline   ? "baseline"
                             : phase == Phase::Attack   ? "attack"
                             : phase == Phase::Recovery ? "recovery"
                                                        : "done";
    const long failed = connect_failed_total + setup_failed_total;

    // "service available" is the whole point of the run, so it says what it
    // knows and, when there is no probe, that it does not know.
    char avail[64];
    if (!prober) {
      std::snprintf(avail, sizeof(avail), "%s", "not measured (--no-probe)");
    } else if (log.probes.empty()) {
      std::snprintf(avail, sizeof(avail), "%s", "waiting for first probe");
    } else {
      const auto& p = log.probes.back();
      const bool up = p.state == Availability::Ok;
      if (p.ms >= 0)
        std::snprintf(avail, sizeof(avail), "%s%s%s (%ld ms)",
                      C(up ? kLGreen : kLRed), up ? "YES" : "NO", C(kReset),
                      p.ms);
      else
        std::snprintf(avail, sizeof(avail), "%s%s%s", C(up ? kLGreen : kLRed),
                      up ? "YES" : "NO", C(kReset));
    }

    if (!use_colour() || verbose_log()) {
      // Appended, not redrawn: a log wants one line per second, in order.
      char clock[16] = {0};
      const time_t wall = ::time(nullptr);
      struct tm tmv;
      if (::localtime_r(&wall, &tmv) != nullptr)
        std::strftime(clock, sizeof(clock), "%H:%M:%S", &tmv);
      std::fprintf(stderr,
                   "%s [%4lds %-8s] initializing=%d pending=%d connected=%d"
                   " error=%ld closed=%ld available=%s\n",
                   clock,
                   secs, phase_name, setting_up, connecting, held, failed,
                   peer_closed_total, avail);
      std::fflush(stderr);
      return;
    }

    if (status_lines_ > 0) std::fprintf(stderr, "\x1b[%dA", status_lines_);
    int lines = 0;
    auto row = [&](const char* label, const char* fmt, ...) {
      char value[96];
      va_list ap;
      va_start(ap, fmt);
      std::vsnprintf(value, sizeof(value), fmt, ap);
      va_end(ap);
      std::fprintf(stderr, "\x1b[2K%s%-21s%s%s\n", C(kLGreen), label, value,
                   C(kReset));
      ++lines;
    };

    // The stamp is part of the redrawn block, so it counts towards the lines to
    // move back over. The classic prints one above every status dump.
    std::fprintf(stderr, "\x1b[2K%s%s:%s\n", C(kBlue), stamp_now().c_str(),
                 C(kReset));
    std::fprintf(stderr, "\x1b[2K%sslow HTTP test status on %s%ld%s%s second"
                         " (%s)%s\n\x1b[2K\n",
                 C(kLGreen), C(kGreen), secs, C(kLGreen),
                 ordinal_suffix(secs), phase_name, C(kReset));
    lines += 3;
    row("initializing:", "%d", setting_up);
    row("pending:", "%d", connecting);
    row("connected:", "%d", held);
    row("error:", "%ld", failed);
    row("closed:", "%ld", peer_closed_total);
    row("service available:", "%s", avail);
    status_lines_ = lines;
    std::fflush(stderr);
  }

  bool build_setup_plan(std::string& err) {
    if (cfg.target.tls()) {
      if (!TlsContext::available()) {
        // The wording is load-bearing: tests and CI grep for "no TLS backend"
        // to recognise this refusal, so it must stay the canonical phrase.
        err =
            "this build has no TLS backend, so https targets cannot be tested"
            " (built with -DSLOWHTTP_TLS=OFF). Rebuild with OpenSSL, or use an"
            " http:// URL.";
        return false;
      }
      tls = TlsContext::create(/*verify_peer=*/false, err, cfg.http2);
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
      case Mode::RapidReset:  log.meta.mode_flag = "--rapid-reset"; break;
      case Mode::Continuation:
        log.meta.mode_flag = "--continuation-flood"; break;
    }
    // A flag that does not reproduce the run is worse than none: -X alone
    // describes a different attack from the one that was carried out.
    if (cfg.http2 && cfg.mode == Mode::SlowRead)
      log.meta.mode_flag += " --http2";
    // Taken from the attack rather than from the mode enum. mode_name() knows
    // only the mode, so with --http2 it called an HTTP/2 slow read "slow read"
    // -- and the report is the artifact people attach to tickets. A reader
    // would have concluded that HTTP/1.1 slow read denied the service, when it
    // was CVE-2019-9517, a different attack with different mitigations, and
    // nothing in the HTML said HTTP/2 at all. The attack names itself, so this
    // stays right as attacks are added.
    log.meta.mode_label = attack.name();
    log.meta.attack_http2 = cfg.http2;
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
    // Wall-clock milestones for the whole process, not just the measured run.
    //
    // Every instrument so far covered one segment and the cost kept turning up
    // outside it: a run whose teardown took 0.10 s still took 959 s in total,
    // and nothing in the output accounted for the difference. This brackets
    // each phase so the next unexplained wait names itself.
    const TimePoint t_enter = Clock::now();
    TimePoint t_resolved = t_enter;
    std::string err;
    if (!build_setup_plan(err)) {
      std::fprintf(stderr, "Error: %s\n", err.c_str());
      return 2;
    }
    if (!addr.resolve(cfg.connect_host(), cfg.connect_port(), err,
                      cfg.address_family)) {
      std::fprintf(stderr, "Error: cannot resolve %s (%s)\n",
                   cfg.connect_endpoint().c_str(), err.c_str());
      return 2;
    }
    t_resolved = Clock::now();
    fill_meta();

    reactor = Reactor::create();
    closer.reset(new Closer(closer_threads(cfg.connections)));

    // Refuse an impossible connection count before opening a single socket.
    // Discovering the ceiling at runtime means thousands of sockets already
    // open and a partial, misleading result; saying so now costs nothing.
    // kReservedFds covers the probe, stdio and the resolver.
    // Covers stdio, the probe, the resolver, and the bounded close queue --
    // those descriptors are open until a closer thread gets to them.
    const std::size_t kReservedFds = 8 + static_cast<std::size_t>(kMaxPendingCloses);
    const std::size_t reactor_cap = reactor->max_descriptors();
    if (reactor_cap > 0 &&
        static_cast<std::size_t>(cfg.connections) + kReservedFds > reactor_cap) {
      std::fprintf(stderr,
                   "Error: -c %d exceeds what this platform's poll() backend can"
                   " watch (%zu descriptors, minus %zu reserved).\n"
                   "       This is a fixed OPEN_MAX ceiling; raising the file"
                   " descriptor limit does not move it.\n"
                   "       Use -c %zu or fewer.\n",
                   cfg.connections, reactor_cap, kReservedFds,
                   reactor_cap - kReservedFds);
      return 2;
    }

    // Descriptors next. The soft limit is 256 on a stock macOS shell, so a
    // -c above that fails every socket() with EMFILE -- which, before this
    // check existed, surfaced as "the target may be down".
    {
      std::string fd_error;
      if (!ensure_descriptor_limit(cfg.connections + static_cast<int>(kReservedFds),
                                   fd_error)) {
        std::fprintf(stderr, "Error: %s\n", fd_error.c_str());
        return 2;
      }
    }

    conns.resize(static_cast<std::size_t>(cfg.connections));
    for (std::size_t i = 0; i < conns.size(); ++i)
      conns[i].id = static_cast<ConnId>(i);

    signal(SIGPIPE, SIG_IGN);

    if (cfg.probe_enabled) {
      prober.reset(new Prober(cfg, tls));
      std::string perr;
      // The address the attack is using, so the oracle cannot drift onto a
      // different one. Empty when a proxy is in play, where the probe is meant
      // to go elsewhere.
      const std::string pinned =
          (cfg.proxy.enabled() || cfg.probe_proxy.enabled())
              ? std::string()
              : ResolvedAddr::numeric_host(current_addr());
      if (!prober->start(perr, cfg.address_family, pinned)) {
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
    // Laid out like the classic tool's banner: one aligned label per setting,
    // in the same order and mostly the same words, so anyone who has read one
    // can read the other. The additions are the ones this session showed were
    // worth having -- the address actually chosen (a dual-stack host can send
    // consecutive runs down different networks) and the effective mode.
    if (chatty()) {
      auto row = [](const char* label, const char* fmt, ...) {
        char value[256];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(value, sizeof(value), fmt, ap);
        va_end(ap);
        std::fprintf(stderr, "%s%-32s%s%s%s\n", C(kBlue), label, C(kLBlue),
                     value, C(kReset));
      };

      std::fprintf(stderr, "%s\tslowhttptest-ng version %s%s\n", C(kLBlue),
                   kToolVersion, C(kReset));
      std::fprintf(stderr, " - %s -\n\n", kProjectUrl);

      // Upper-cased to match the classic tool, which prints SLOW READ.
      std::string type = attack.name();
      for (char& ch : type) ch = static_cast<char>(::toupper(ch));
      row("test type:", "%s", type.c_str());
      row("number of connections:", "%d", cfg.connections);
      row("URL:", "%s", log.meta.target_url.c_str());
      row("verb:", "%s", cfg.effective_verb().c_str());
      row("resolved address:", "%s (%zu candidate%s)",
          ResolvedAddr::describe(current_addr()).c_str(),
          addr.candidates().size(),
          addr.candidates().size() == 1 ? "" : "s");
      if (cfg.mode == Mode::SlowRead) {
        row("receive window range:", "%d - %d", cfg.window_lower,
            cfg.window_upper);
        row("read rate from receive buffer:", "%d bytes / %lld sec",
            cfg.read_len, static_cast<long long>(cfg.read_interval.count()));
      } else {
        row("interval between follow up data:", "%lld seconds",
            static_cast<long long>(cfg.interval.count()));
      }
      row("connections per seconds:", "%d", cfg.rate);
      // Printed next to the attack's address on purpose: when they differ
      // without a proxy to explain it, the run is measuring one endpoint and
      // reporting on another.
      if (prober && !prober->endpoint().empty())
        row("probe endpoint:", "%s%s", prober->endpoint().c_str(),
            (cfg.proxy.enabled() || cfg.probe_proxy.enabled()) ? " (via proxy)"
                                                               : "");
      row("probe:", "%s", probe_desc);
      row("test duration:", "%lld seconds",
          static_cast<long long>(cfg.duration.count()));
      row("using proxy:", "%s",
          cfg.proxy.enabled() ? cfg.proxy.host.c_str() : "no proxy");
      std::fprintf(stderr, "\n");
    }

    // Installed only now: name resolution is behind us, and getaddrinfo(3)
    // cannot be interrupted, so catching the signal any earlier would swallow a
    // Ctrl-C for as long as a slow resolver takes.
    install_cancel_handler();

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
    // Set when ramp() ran out of budget with slots still to fill; the loop
    // then skips its sleep so opening continues without stalling anything.
    bool ramp_pending = false;
    bool reactor_failed = false;
    bool cancelled = false;
    for (;;) {
      TimePoint now = Clock::now();

      // Cancel is handled here rather than in the signal handler: closing
      // thousands of filter-held descriptors has to go through the closer pool,
      // and none of that is legal in a handler.
      if (g_cancelled) {
        cancelled = true;
        break;
      }

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
          ramp_pending = ramp(now);
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
            // Only when there is a probe to watch recovery with. Taking the
            // load off is the point of closing here, and with no probe nothing
            // observes the result -- while closing thousands of remote sockets
            // can itself take minutes, which would be spent for nothing.
            if (prober) close_all();
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
      // Still ramping: come straight back after servicing whatever is ready,
      // rather than idling until the next timer.
      if (ramp_pending) timeout = std::chrono::milliseconds(0);
      // While connections are still being opened, wake often enough that the
      // per-second allowance is spent in small handfuls rather than saved up and
      // released in one burst. Removing the initial burst above achieves nothing
      // on its own: a loop that sleeps a full second between ramp passes then
      // finds a whole second of allowance waiting and opens it all at once,
      // which is the same burst arriving later.
      if (target_conns > 0 && active_conns < target_conns)
        timeout = std::min(timeout, kRampWake);

      events.clear();
      if (reactor->wait(events, timeout) < 0) {
        // The reactor cannot wait any more. Retrying would spin at the speed of
        // the failing syscall, so stop -- and do not draw a conclusion from a
        // run whose event loop stopped working partway through.
        std::fprintf(stderr, "\n\nError: %s\n",
                     reactor->last_error().c_str());
        reactor_failed = true;
        break;
      }

      for (const auto& ev : events) {
        if (prober && ev.fd == probe_reg_fd && ev.fd >= 0) {
          prober->on_event(Clock::now(), ev.readable, ev.writable, ev.error);
          continue;
        }
        Conn* c = conn_by_fd(ev.fd);
        if (!c || !c->active) continue;
        if (ev.error) {
          if (c->sock.state() == SockState::Connecting) {
            // Ask the socket why before closing it; poll() only said "error".
            note_connect_failure(c->sock.finish_connect()
                                     ? 0
                                     : c->sock.connect_errno());
            close_slot(*c);
            continue;
          }
          // A hangup routinely arrives with the bytes that explain it still
          // unread: kqueue sets EV_EOF alongside pending data, and a proxy that
          // answers CONNECT with 403 and closes produces exactly that. Writing
          // the connection off here discarded the reply along with the only
          // reason the run had -- and because the loss landed in peer_closed
          // rather than setup_failed, the scheme-mismatch heuristic downstream
          // then read "TCP up, no handshake, nothing failed" and told the
          // operator to try http://, which is confidently wrong advice about a
          // proxy that simply refused the tunnel.
          //
          // So drain setup first. If it concludes, it closes the slot itself
          // with the real reason; if it still wants bytes that are never coming,
          // fall through and count the hangup as before.
          if (!c->sock.ready()) {
            drive_setup(*c);
            if (!c->active) continue;
          }
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
        reap_stalled(now);
        status_line(now);
        next_status = now + kStatusInterval;
      }
    }

    // Cancelled runs measured nothing worth reporting, so nothing is written.
    // The descriptors still have to be closed, and doing it here through the
    // pool is what keeps it minutes rather than hours.
    if (cancelled) {
      interrupt_status();
      if (chatty()) {
        const long ended_s = std::chrono::duration_cast<std::chrono::seconds>(
                                 Clock::now() - start).count();
        std::fprintf(stderr, "\n%s%s:%s\n", C(kBlue), stamp_now().c_str(),
                     C(kReset));
        std::fprintf(stderr, "%sTest ended on %ld%s second%s\n", C(kLBlue),
                     ended_s, ordinal_suffix(ended_s), C(kReset));
        std::fprintf(stderr, "%sExit status:%s %s%s\n", C(kLBlue), C(kReset),
                     exit_status_text(ExitStatus::Cancelled), C(kReset));
      }
      const int left = close_all();
      if (closer && left > 0) {
        const TimePoint began = Clock::now();
        // Every worker starts a close at the same instant and each one waits out
        // the same timeout, so for the first second the count does not move at
        // all. Elapsed time is what shows the process is alive during exactly
        // the window in which someone decides whether to kill it.
        closer->drain([&](long remaining) {
          const long secs = std::chrono::duration_cast<std::chrono::seconds>(
                                Clock::now() - began).count();
          std::fprintf(stderr,
                       "\r  closing %ld of %d connections (%lds elapsed)%s   ",
                       remaining, left, secs,
                       g_cancelled > 1 ? " -- still working, killing is slower"
                                       : "");
          std::fflush(stderr);
        });
        std::fprintf(stderr, "\r  closed %d connection(s)%40s\n", left, "");
      }
      std::fflush(nullptr);
      ::_exit(130);  // 128 + SIGINT, the conventional shell code
    }

    const TimePoint stop_at = Clock::now();
    if (log.attack_end_s == 0 && log.attack_start_s > 0)
      log.attack_end_s = elapsed(stop_at);
    log.run_end_s = elapsed(stop_at);
    log.conns.push_back(
        ConnSample{log.run_end_s, held_connections(), target_conns});
    // Nothing is closed here on purpose. The results are what the operator is
    // waiting for and they cost microseconds; teardown happens below, once they
    // are on screen.
    status_line(stop_at);
    interrupt_status();

    // Connections the engine wrote to and the kernel never transmitted on.
    //
    // Measured against a real target: ~10% of a 1500-connection run ended with
    // send() having returned success, nothing queued, an empty send buffer, and
    // the kernel reporting zero bytes ever sent. Those connections were counted
    // as held while applying no load at all, which overstates the test -- the
    // single worst failure mode for a tool whose output people put in reports.
    //
    // On macOS this is what a content filter looks like from inside the process:
    // send() succeeds into the filter's queue and the bytes never reach the
    // wire. See net.cfil.* -- and note that the same filter bills close(2) up to
    // net.cfil.close_wait_timeout per socket on the way out.
    long undelivered = 0;
    for (const auto& c : conns) {
      if (!c.active || !c.sock.ready() || c.sent_bytes <= 0) continue;
      const long tx = c.sock.kernel_tx_bytes();
      if (tx == 0) ++undelivered;
    }

    // The classic tool's closing lines, same words and order. They say what
    // happened in a form anyone who has used that tool already reads; the
    // machine-readable "Done (...)" line below stays for scripts and tests.
    if (chatty()) {
      ExitStatus status = ExitStatus::TimeLimit;
      if (reactor_failed) {
        status = ExitStatus::Unexpected;
      } else if (ready_total == 0) {
        // Never got a usable connection. Keyed on that rather than on gave_up,
        // which only trips after a run of consecutive failures -- a short run
        // against a dead port can reach its duration first and would otherwise
        // report "Hit test time limit", which is true and useless.
        //
        // "nothing is listening" and "it never answered" are separate answers
        // with separate remedies, and the classic separates them too.
        status = dominant_connect_errno() == ECONNREFUSED
                     ? ExitStatus::ConnectionRefused
                     : ExitStatus::CannotConnect;
      } else if (held_connections() == 0 && peer_closed_total > 0) {
        status = ExitStatus::AllClosed;
      }
      const long ended_s =
          std::chrono::duration_cast<std::chrono::seconds>(stop_at - start)
              .count();
      std::fprintf(stderr, "\n%s%s:%s\n", C(kBlue), stamp_now().c_str(),
                   C(kReset));
      std::fprintf(stderr, "%sTest ended on %ld%s second%s\n", C(kLBlue),
                   ended_s, ordinal_suffix(ended_s), C(kReset));
      std::fprintf(stderr, "%sExit status:%s %s%s\n", C(kLBlue), C(kReset),
                   exit_status_text(status), C(kReset));
    }

    const char* why = reactor_failed ? "event loop failed"
                      : gave_up      ? "giving up"
                                     : "finished";
    if (chatty())
      std::fprintf(stderr,
                 "\n\nDone (%s). opened=%ld connected=%ld ready=%ld"
                 " peer_closed=%ld connect_failed=%ld setup_failed=%ld"
                 " connect_timeout=%ld\n",
                 why, opened_total, connected_total, ready_total,
                 peer_closed_total, connect_failed_total, setup_failed_total,
                 connect_timeout_total);

    if (undelivered > 0 && chatty()) {
      std::fprintf(stderr,
                   "\nWARNING: %ld connection(s) never put their request on the"
                   " wire.\n"
                   "         The request was written and accepted locally, but"
                   " the kernel reports\n"
                   "         zero bytes sent -- something between this process"
                   " and the network is\n"
                   "         holding them. They applied no load, so the effective"
                   " connection count\n"
                   "         was %d, not %d.\n",
                   undelivered, cfg.connections - static_cast<int>(undelivered),
                   cfg.connections);
      const long cfil = active_content_filters();
      if (cfil > 0)
        std::fprintf(stderr,
                     "         macOS reports %ld active content filter(s)"
                     " (net.cfil.active_count).\n"
                     "         That is the usual cause here, and it also slows"
                     " connection teardown.\n",
                     cfil);
    }

    // Never report success for a test that never reached the target: a silent
    // exit 0 here would make CI and scripts treat an unreachable host as a pass.
    if (ready_total == 0) {
      // Name the actual cause. Blaming the target for a local descriptor or
      // port limit sends the operator to debug the wrong machine entirely.
      // Not `err`: that name already holds the setup/resolve error string for
      // the whole of run(), and an int of the same name shadowing it here is
      // one careless edit away from printing the wrong thing.
      const int connect_err = dominant_connect_errno();
      const std::string advice = advice_for(connect_err);
      std::fprintf(stderr,
                   "\nERROR: no usable connection was ever established to %s"
                   " (tried %zu resolved address(es)) -- nothing was actually"
                   " tested.\n",
                   cfg.connect_endpoint().c_str(), addr.candidates().size());
      if (connect_err != 0) {
        std::fprintf(stderr, "       Every attempt failed with: %s\n",
                     std::strerror(connect_err));
        if (!advice.empty())
          std::fprintf(stderr, "       %s\n", advice.c_str());
        if (blame_for(connect_err) == Blame::Local)
          std::fprintf(stderr,
                       "       This is a limit on THIS machine. The target was"
                       " never actually reached, so it is not implicated.\n");
      } else {
        std::fprintf(stderr,
                     "       The target may be down, firewalled, on another"
                     " port, or rejecting the TLS/proxy setup.\n");
      }
      log.exit_code = 3;
    }

    // At -v 4 print the whole distribution: with several causes mixed together
    // the dominant one alone can be misleading.
    if (cfg.log_level >= 4 && !connect_errnos_.empty()) {
      std::fprintf(stderr, "\nconnect failures by cause:\n");
      for (const auto& kv : connect_errnos_)
        std::fprintf(stderr, "  %8ld  %s\n", kv.second,
                     std::strerror(kv.first));
    }
    scheme_mismatch_hint();

    // A run whose event loop stopped working measured nothing trustworthy after
    // that point, so it gets no verdict and no report. Printing "SERVICE HELD"
    // because the probe went quiet along with everything else would be the worst
    // possible failure mode for this tool.
    if (reactor_failed) {
      std::fprintf(stderr,
                   "\nNo verdict: the event loop failed partway through, so"
                   " anything measured after that point is not trustworthy.\n");
      return 4;
    }

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
    // Teardown, timed, after the results rather than before them.
    //
    // Closing every socket explicitly is what the classic tool does, and it is
    // the cheaper of the two ways out: 1500 established remote connections close
    // in well under a second, where leaving them to the kernel at _exit() left
    // the process alive for another 59 after its results were on screen.
    //
    // It stays timed and printed. Teardown against a real peer has taken
    // anywhere from 0.07 s to 169 s for identical runs -- it depends on what
    // else is in the socket path, and on this machine a Network Extension
    // content filter is -- so an operator who waits is told what they are
    // waiting for rather than left watching a frozen prompt.
    const TimePoint teardown_start = Clock::now();
    const int torn_down = close_all();
    // close_all only hands the descriptors over now, so the cost is here. The
    // threads absorb the per-socket stall in parallel; what is left is a wait
    // that says what it is waiting for rather than a frozen prompt.
    if (closer && torn_down > 0) {
      closer->drain([&](long left) {
        if (chatty()) {
          std::fprintf(stderr, "\r  closing connections: %ld of %d left   ",
                       left, torn_down);
          std::fflush(stderr);
        }
      });
      if (chatty() && torn_down >= 100)
        std::fprintf(stderr, "\r%50s\r", "");
    }
    if (chatty() && torn_down > 0) {
      const double secs =
          std::chrono::duration<double>(Clock::now() - teardown_start).count();
      std::fprintf(stderr, "  teardown: %.2fs to close %d connection(s)\n",
                   secs, torn_down);
      if (cfg.log_level >= 4)
        std::fprintf(stderr, "    close(2) %.2fs, bookkeeping %.2fs\n",
                     close_syscall_s, close_bookkeep_s);
    }

    // _exit rather than return: unwinding would run ~Socket() on every slot a
    // second time. The report files are already closed by write_reports, and
    // stderr is unbuffered,
    // so nothing is lost by skipping the usual teardown.
    if (chatty()) {
      const TimePoint t_end = Clock::now();
      auto seg = [](TimePoint a, TimePoint b) {
        return std::chrono::duration<double>(b - a).count();
      };
      // Anything the shell reports beyond this total happened after _exit(),
      // in the kernel's own teardown of the process.
      std::fprintf(stderr,
                   "  timeline: resolve %.2fs, run %.2fs, teardown %.2fs"
                   " -- %.2fs in process\n",
                   seg(t_enter, t_resolved), seg(t_resolved, teardown_start),
                   seg(teardown_start, t_end), seg(t_enter, t_end));
    }
    std::fflush(nullptr);
    ::_exit(log.exit_code);
  }
};

Engine::Engine(const Config& cfg, Attack& attack)
    : impl_(new Impl(cfg, attack)) {}
Engine::~Engine() = default;
int Engine::run() { return impl_->run(); }

}  // namespace slowhttp
