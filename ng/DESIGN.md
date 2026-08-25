<!-- SPDX-License-Identifier: Apache-2.0 -->
# slowhttptest-ng — design

Rationale for the rewrite in `ng/`. Records the decisions and *why* they were
made, so they don't have to be relitigated. The code says what; this says why.

> ⚠️ slowhttptest is an application-layer DoS testing tool. Only run it against
> systems you are authorized to test.

## 1. Why rewrite at all

The original has aged well functionally but carries the usual costs of 2011-era
C++: a hand-rolled `select()` loop bounded by `FD_SETSIZE`, one large
`SlowHTTPTest` class holding ~40 members that owns config, sockets, statistics
and reporting at once, raw `char[1024]` buffers, `std::auto_ptr` behind a
`HAVE_CXX11` macro, and attack logic interleaved with I/O so nothing can be
tested without a live socket.

More importantly, the threat model has moved. The classic modes assume
**thread-per-connection** servers. Modern event-driven servers (nginx, Envoy, Go,
Netty) barely notice a held connection, which is why the tool finds fewer
vulnerable targets than it did in 2011. Staying useful means being able to add
new attack classes cheaply — which needs an architecture where an attack is a
small, testable unit.

## 2. Language: C++17

**Decided: modern C++17 + CMake, OpenSSL as the only mandatory dependency.**

The existing code is already C++ (`.cc`), so this is modernization rather than a
port. Locked defaults:

| | |
|---|---|
| Standard | C++17 (GCC 7+/Clang 5+ — covers every supported distro) |
| Build | CMake ≥ 3.16 (in Debian oldstable, RHEL 8+) |
| Reactor | hand-rolled epoll/kqueue/poll, zero extra deps |
| TLS | system OpenSSL, behind a `TlsBackend` interface |
| License | Apache 2.0, retained (matches existing source headers) |

### Why not Rust

Rust would produce nicer code. It was rejected on **distro packaging**, not on
language merit — slowhttptest is packaged by many distros today, and a rewrite
pushes recurring work onto those maintainers:

1. **Debian's crate-explosion model.** Dependencies aren't vendored into one
   package; each crate becomes its own `librust-*-dev` package. A `tokio` +
   `rustls` core pulls dozens of transitive crates, each of which someone must
   package and keep updated.
2. **Offline builds.** Distro build farms have no network. Cargo wants
   crates.io, so the whole graph must be vendored into the tarball and still
   satisfy per-distro provenance policy. A C++/OpenSSL build fetches nothing.
3. **Toolchain age on LTS targets.** RHEL, Debian oldstable and older Alpine may
   ship a Rust behind what current `tokio`/`rustls` need. Every supported distro
   already has a C++17 compiler and `libssl-dev`.
4. **Crypto vendoring.** `rustls` pulls `ring`/`aws-lc-rs`, which bundle their own
   crypto; distros prefer linking the system OpenSSL.
5. **`unsafe` where it matters most.** Slow read needs `SO_RCVBUF` and raw socket
   options — `libc` and `unsafe` in exactly the module that most needs control,
   which erases much of the safety argument.

None of these is a dead end (ripgrep, fd are packaged fine). The point is the
burden lands on the maintainer, which cuts against the compatibility goal.
**Revisit if priorities shift** to Homebrew + Docker + static release binaries
with the maintainer owning packaging.

## 3. Architecture

```
ng/
  include/slowhttp/   public headers (attack interface, config, engine, reactor)
  src/net/            sockets, address resolution, reactor backends
  src/engine/         the event loop
  src/attacks/        one file per attack
  src/config/         CLI parsing
  cli/                thin front-end
  tests/              unit tests, mock server, end-to-end suite
```

Two rules carry most of the design:

**1. `libslowhttp` is split from the CLI.** Attacks are unit-testable without a
socket, and the library is embeddable.

**2. Attacks never do I/O.** An attack is a per-connection state machine whose
hooks (`on_connect`, `on_timer`, `on_readable`) return an `Action` —
send / read / close / reconnect, plus an optional timer. The engine owns
sockets, timers, socket options, and the event loop. Attacks decide *what bytes
to dribble and when*; nothing else.

This is why each attack is ~80 lines and why the whole protocol contract can be
asserted in a unit test with no network.

### The reactor

`Reactor` is an interface over readiness multiplexing. `poll()` ships as the
portable default (Linux/macOS/BSD, no dependencies). epoll and kqueue backends
drop in behind the same interface without touching the engine — the reason the
abstraction exists at all, since `select()`'s `FD_SETSIZE` ceiling is a real
limit on the original.

## 4. The four attacks, and why each is distinct

Each attacks a different point of the request lifecycle, and — the operationally
important part — **each is stopped by a different timeout**. A server hardened
against one can be wide open to the next. This is measured, not assumed; see
`tests/e2e_attacks.py`.

| Mode | Withheld | Server blocks in | Defense | Header timeout helps? |
|---|---|---|---|---|
| `-H` slow headers | end of headers | reading headers | header timeout | yes |
| `-B` slow body | body promised by `Content-Length` | reading body | **body** timeout | **no** |
| `-X` slow read | acknowledgement of the response | sending | **send** timeout | **no** |
| `-R` range | nothing — amplification | CPU/memory | patched since 2011 | n/a |

The negative results are the valuable ones: slow body and slow read both
complete their headers instantly, so a header timeout has nothing to fire on.

**Slow read** deserves note as the only mode whose mechanism is TCP flow control
rather than HTTP. It needs `SO_RCVBUF` set *before* `connect()` (otherwise it
doesn't shape the advertised window during the handshake) and it must **not**
drain the socket — which is why `Attack` grew `conn_options()` and
`wants_read_events()`. Kernels clamp `SO_RCVBUF` to a floor and typically return
double the request, so the tool reports what was actually granted rather than
assuming the request took effect.

**Range** is a regression check, not a live exploit: CVE-2011-3192 was patched in
2011. It answers "is this still vulnerable?".

## 5. HTTP/2 (implemented; where the value was)

Slow read works on HTTP/2 and is *stronger* there, for two reasons: HTTP/2 adds
an explicit application-layer flow-control window (`SETTINGS_INITIAL_WINDOW_SIZE`,
`WINDOW_UPDATE`) that isn't subject to kernel clamping, and multiplexing means
one connection can pin ~100 streams — evading the per-IP connection limits that
are the standard Slowloris mitigation.

The most damaging variant is **CVE-2019-9517 (Internal Data Buffering)**: open the
HTTP/2 window so the server generates and queues a large response, while starving
the TCP window so it can never drain. That piles data into the server's
*application* buffers, which are far more expensive than kernel socket buffers.
**The existing slow-read machinery is exactly what this needs** — the missing
piece is only framing (frame codec + a minimal HPACK encoder; static-table-only
suffices for sending requests).

Worth adding once framing exists: **Rapid Reset (CVE-2023-44487)** — the most
consequential HTTP DoS of the last decade and untouched by the current tool —
and the **CONTINUATION flood**, which is the true Slowloris analogue and which
many stacks buffer unboundedly *without logging*.

All three are implemented: `--http2` for slow read, `--rapid-reset`, and
`--continuation-flood`. The framing is send-only -- no frame parser, no HPACK
decoder, no dynamic table -- because none of these attacks needs to understand
what the server says, only to make it hold something.

Verified against nginx 1.31.4 rather than against a validator written alongside
the encoder, which could not catch a misreading shared by both. nginx logged no
protocol errors; slow read left it holding 326 KB per connection with our TCP
window at zero; rapid reset and the CONTINUATION flood were both met by nginx
closing the connection, which is the mitigation working and which the tool
reports as `peer_closed`.

Worth recording, because it is the finding rather than the feature: nginx alone
is a poor target for HTTP/2 slow read. It is event driven and its own buffering
is bounded, so it holds. What gives way is whatever is behind it -- with
`proxy_buffering off`, four client connections became 128 pinned upstream
requests against an eight-worker backend and denied the service outright. The
32x multiplier is `--h2-streams`, and per-IP connection limits, the standard
Slowloris mitigation, saw four connections.

## 6. Measuring the outcome, not the attack

The original tool reports what the *attacker* did: sockets opened, connected,
pending. A reader has to infer the thing they actually came for. This rewrite
measures the thing directly.

### The availability probe is the oracle

One short-lived connection at a time, sending an entirely ordinary complete
request and timing the first response byte. Everything else — the verdict, the
report, the capacity search — is derived from it. Held sockets are not evidence:
an event-driven server will happily hold every connection you can open and serve
every real client throughout.

Three per-sample states, because "answered slowly" is a different finding from
"did not answer". The status code is deliberately *not* used to decide
availability: a 503 is a served response, and treating it as a denial would
conflate "refused me" with "never answered me".

`-e` routes only the probe through a proxy, so availability can be measured from
a different network path than the one being saturated.

**Samples are not evenly spaced**, and this matters more than it looks. A probe
that times out occupies the full `-p` before it can be recorded; a served one
returns in milliseconds. Counting samples would therefore overstate availability
by roughly the ratio of timeout to latency. Every duration in the report is
computed from the span each sample actually stands for, not from sample counts.

### Four outcomes, one of which is a refusal to answer

`denied` / `degraded` / `held` / **`inconclusive`**. The last is the point: with
an unhealthy baseline or too few samples, the tool declines rather than reporting
a reassuring `held` it never measured. A pre-attack baseline exists so the report
can distinguish "we broke it" from "it was already broken", and a post-attack
recovery watch separates exhaustion from a crash.

`held` is stated just as conditionally as `denied` — it is scoped to the
connection count tested and says so.

### The denial threshold is a bracket or it is nothing

`--capacity` holds connections at each level, probes, then steps up, so the
resolution is the step size. Reported as `64 < n <= 96`, never a point estimate.

A plain run refuses to report a threshold at all, and says why: at `-r 50` with a
2 s probe interval the ramp covers 100 connections between samples, so any number
read off it would be an artifact of ramp timing rather than a property of the
server.

### One event log, two renderers

HTML and JSON are generated from the same in-memory `EventLog`, so they cannot
disagree. The HTML is fully self-contained — inline CSS, inline SVG, inline data
— because the original loads Google Chart Tools over the network and renders
nothing offline, in Docker, or air-gapped. The JSON carries a pass/fail against a
stated availability threshold for CI gating.

Exit code stays 0 for a completed measurement regardless of outcome: a successful
test that found a denial is not a failed run. CI gates on the JSON.

Not planned: CSV and JUnit output (considered, dropped).

## 7. Replacing the original

`slowhttptest-ng` is meant to become `slowhttptest`. Both trees build today and
install side by side; the rewrite is not a fork.

Flag compatibility is complete — every classic flag, same meaning — because the
cost of breaking it lands on the maintainer through packagers and existing
users' scripts. Three deliberate breaks remain, each judged worth it:

| Break | Why |
|---|---|
| CSV output dropped | JSON carries the same run plus the verdict and a CI gate; two serializations of one event log is a drift risk for no gain |
| exit codes `2`/`3` instead of `-1` | `-1` says only "something went wrong"; `3` specifically means *nothing was tested*, which is the failure mode that silently passes CI |
| report is availability-centric | socket-state reporting makes the reader infer the thing they came for |

Packaging is deliberately conventional, because distro packaging is the whole
reason this is C++ (§2): `GNUInstallDirs`, `DESTDIR` honoured, a man page, `-V`
reporting whether TLS is compiled in, and OpenSSL as the only dependency.
`libslowhttp` is *not* installed — its headers still move, and shipping them
would promise an API stability the project cannot yet keep.

The switch itself is a rename plus retiring `src/`, once the rewrite has had
real-world exposure under its own name.

## 8. Roadmap

Done: all four HTTP/1.1 attack modes, reactor, engine, CLI parity, TLS/https, proxying
(`-d`/`-e`, including `CONNECT`), the availability probe (`-p`), the capacity
staircase, HTML + JSON reporting, install rules, man page, tests, CI.

Also done since: kqueue, HTTP/2 (all three attacks), `-4`/`-6`, a `./configure`
front end for packagers, and the report naming the protocol it actually used.

Remaining:

1. **An epoll backend for Linux.** kqueue is done and was the urgent half; the
   measurements that motivated it are kept below because they say something the
   headline does not -- CPU was never the problem:

   | connections | held | system CPU (40 s run) | share of a core |
   |---|---|---|---|
   | 1 000 | 1 000 | 0.27 s | 0.7% |
   | 2 000 | 2 000 | 0.66 s | 1.7% |
   | 4 000 | 4 000 | 1.84 s | 4.7% |
   | 8 000 | 8 000 | 4.42 s | 11.2% |

   Cost grows about `N^1.36` — mildly superlinear, not quadratic, because
   `fire_timers` drains every due timer per wake so wakeups batch rather than
   scaling with N. **CPU is therefore not the reason to do this.**

   The reason is that `poll()` has a hard ceiling. On Darwin it rejects
   `nfds > OPEN_MAX` with `EINVAL`, and `OPEN_MAX` is a compile-time 10 240 that
   no file-descriptor limit raises (measured: the syscall starts failing at
   nfds 10 256). kqueue has no such limit. So on macOS/BSD a kqueue backend is
   not an optimization — it is the only way past ~10 k connections, which is
   well inside the range needed to stress a modern event-driven server (§1).

   On Linux `poll()` has no `OPEN_MAX` limit, so the ceiling there is the O(n)
   scan and `RLIMIT_NOFILE` instead. That has not been measured.

   Do kqueue first: it is the platform where the wall is hard, near, and hit by
   the maintainer's own machine.
2. ~~**HTTP/2**~~ — done; see §5. Slow read (CVE-2019-9517), rapid reset
   (CVE-2023-44487) and the CONTINUATION flood, all verified against nginx
   1.31.4.
