# slowhttptest-ng

A ground-up, modern C++17 rewrite of slowhttptest. This `ng/` tree lives alongside
the original `src/` and does **not** touch it; the old tool keeps building until the
rewrite reaches feature parity.

> ⚠️ slowhttptest is an active application-layer DoS testing tool. Only run it
> against systems you are authorized to test.

See [DESIGN.md](DESIGN.md) for the architecture, the language decision and its
rationale, and the roadmap.

## What's implemented

- **Library + CLI split** — `libslowhttp` (engine) is independent of `cli/` and
  unit-testable.
- **Reactor abstraction** (`slowhttp/reactor.hpp`) with a portable `poll()` backend
  that builds on Linux/macOS/BSD. epoll/kqueue backends drop in behind the same
  interface without changing the engine.
- **Attack state-machine interface** (`slowhttp/attack.hpp`) — attacks decide *what
  bytes to dribble and when*; the engine owns all I/O and timers.
- **All four attack modes**, each wired end-to-end against a real target:
  slow headers (`-H`), slow body (`-B`), slow read (`-X`), range (`-R`).
- **TLS / https** over system OpenSSL, with SNI and client certificates from
  `SSL_CERT` / `SSL_KEY` (same environment variables as the classic tool).
- **Proxy support** — `-d` routes all traffic, `-e` routes only the probe.
  https goes through a `CONNECT` tunnel; plain http uses absolute-URI form.
- **Availability probe** (`-p`) — measures whether the *service* is still being
  served, which is the only thing that makes a verdict meaningful.
- **Capacity search** (`--capacity`) — brackets the denial threshold instead of
  guessing at it.
- **Reporting** (`-g`) — self-contained HTML plus machine-readable JSON, both
  generated from one internal event log.
- **Repeatable custom headers** (`-1`/`--header`) for auth and routing, sent on
  the attack *and* the probe, plus request bodies from a literal or file
  (`-P`/`--data`). The tool identifies itself in its User-Agent by default.
- **Backward-compatible CLI flags** (`-H -B -R -X -u -c -r -l -i -x -s -t -f -m
  -j -1 -v -n -z -w -y -k -a -b -d -e -p -g -o -h`), plus `-P`.
- **CMake** build with unit, smoke and end-to-end tests (`ctest`).
- A **deliberately vulnerable mock server** (`tests/mock_slow_server.py`, http or
  https) and a **test proxy** (`tests/mock_proxy.py`), so you can watch a real
  denial of service — not just held sockets.

## Not yet ported

- epoll/kqueue reactor backends (the abstraction is in place; `poll()` works
  everywhere and is the current ceiling on connection counts).
- HTTP/2 attack modes — deliberately deferred, and probably where the remaining
  value is; see
  [DESIGN.md §5](DESIGN.md#5-http2-deferred-but-where-the-value-likely-is).

## Migrating from `slowhttptest`

`slowhttptest-ng` is intended to replace `slowhttptest`. Until it does, the two
build and install side by side.

It accepts **every flag the classic tool does, with the same meanings**, so
existing invocations carry over unchanged. Three things differ, and all three
can bite a script:

| | classic | ng |
|---|---|---|
| `-o base` writes | `base.html` + `base.csv` | `base.html` + **`base.json`** |
| errors exit with | `-1` (255) | `2` usage/config, `3` nothing tested |
| the report is built around | socket state changes | **service availability** |

**CSV output is gone.** If you have something parsing `base.csv`, move it to
`base.json`, which carries the same run in a structured form plus the verdict
and a CI pass/fail. There is no `--csv` compatibility shim.

**Exit codes changed, and 0 now means something narrower**: the test ran to
completion, whatever the outcome. Finding a denial of service is a successful
run, not a failed one — gate on `.criterion.pass` in the JSON rather than on
`$?`.

## Build

OpenSSL is the only mandatory dependency.

```bash
cd ng
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Produces `ng/build/slowhttptest-ng`. On macOS, point CMake at the Homebrew keg if
it isn't found automatically:

```bash
cmake -S . -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
```

On Apple Silicon, check what you built:

```bash
file build/slowhttptest-ng
```

It should say `arm64`. If it says `x86_64`, the binary runs under Rosetta — which
is worth avoiding in a tool that measures someone else's timing. The usual cause
is a `cmake` installed by Intel Homebrew: it is itself an x86_64 binary, so it
reports the host as x86_64 and builds to match. The build now detects that and
targets `arm64` anyway, but it cannot fix a build directory that was already
configured the other way; delete `build/` and configure again.

To build without TLS (https is then refused with an explanation rather than
failing to link):

```bash
cmake -S . -B build -DSLOWHTTP_TLS=OFF
```

### Installing

```bash
cmake --install build --prefix /usr/local
```

Installs the binary and its man page, honouring `DESTDIR` and the standard
`GNUInstallDirs` layout:

```
/usr/local/bin/slowhttptest-ng
/usr/local/share/man/man1/slowhttptest-ng.1
```

### `./configure` also works

If your habits or your packaging scripts expect the GNU dance, it is there:

```bash
./configure --prefix=/usr --disable-tls
make
make check          # unit tests only, ~2 seconds
make install DESTDIR=/tmp/stage
```

`configure` is a wrapper, not a second build system. There is one build
definition in this tree — `CMakeLists.txt` — and the script translates the usual
options into CMake arguments and writes a `Makefile` that delegates to it.
Carrying real autotools alongside CMake would mean two descriptions of the build
drifting apart, and every new source file added twice; the failure mode is
"builds with cmake, fails with make", found by a packager rather than by us.

Unrecognised options are warned about and ignored, as autoconf does. That is not
politeness: `dh_auto_configure` alone passes `--build`, `--infodir`,
`--disable-silent-rules` and more, and a wrapper that rejected them would fail
on the first real packaging attempt. `--host` is refused explicitly, because
cross-compiling needs a CMake toolchain file that this script cannot invent.

`make distclean` removes the build directory and the generated `Makefile`.

### Packaging

CMake underneath, which every distribution build system drives directly
(`dh_auto_configure`, Fedora's `%cmake` macros, Arch, Alpine, Gentoo). What
packagers actually need is that the build behave itself, so:

* `DESTDIR` staging works, with `GNUInstallDirs` for every path.
* `CMAKE_BUILD_TYPE` is only defaulted when the caller has not set one, so
  `RelWithDebInfo` survives.
* No hard-coded `-O2`, `-march` or link flags, so distribution `CXXFLAGS` and
  `LDFLAGS` are honoured rather than overridden.
* No `__DATE__` or `__TIME__` anywhere, so builds are reproducible.
* OpenSSL is the only mandatory dependency, and `-DSLOWHTTP_TLS=OFF` drops it.

Tests are labelled, which matters more than it sounds:

```bash
ctest -L unit     # hermetic, no sockets, ~2 seconds -- run this in a build
ctest             # adds three end-to-end suites that bind loopback ports, ~5 min
```

A build sandbox with restricted networking will fail or hang on the end-to-end
suites, and the usual reaction is to disable testing altogether -- which throws
away the unit tests too, and those are the ones that would catch a miscompile on
an architecture the maintainer does not own.

`libslowhttp` is deliberately **not** installed. It is a static library whose
headers are still moving, and shipping it would be a promise of API stability
the project isn't ready to make; it remains available for in-tree embedding.

`slowhttptest-ng -V` reports the version, the project URL, whether TLS is
compiled in, and the reactor's connection ceiling:

```
slowhttptest-ng 2.0.0
https://github.com/shekyan/slowhttptest
TLS: enabled (OpenSSL)
reactor: poll, max 10240 connections (fixed OPEN_MAX ceiling)
```

Both of the last two matter in a bug report. A build without TLS behaves
differently in a way that is otherwise invisible, and on some platforms — macOS
among them — `poll()` cannot watch more than a fixed `OPEN_MAX` descriptors no
matter what `ulimit -n` says. A `-c` above that ceiling is refused at startup
rather than discovered ten thousand sockets in.

## Try it locally — watch a real denial of service

The mock server is a *deliberately vulnerable* HTTP server: a fixed pool of worker
threads and no timeout on reading request headers. Slow clients pin every worker,
and once the pool is full, legitimate clients can't be served.

```bash
# terminal 1: vulnerable server, 8 workers, serving a real page
python3 tests/mock_slow_server.py 8080 --workers 8

# terminal 2: a normal client is served fine
curl -s --max-time 3 http://127.0.0.1:8080/            # -> 200, the page

# terminal 2: launch the attack (20 slow connections vs 8 workers)
./build/slowhttptest-ng -u http://127.0.0.1:8080/ -c 20 -i 10 -l 120 &

# terminal 2: the same normal client is now starved
curl -s --max-time 5 http://127.0.0.1:8080/ || echo DENIED   # -> DENIED
```

The server prints `workers busy: 8/8 ... [SATURATED - denying new clients]` while
the attack runs, and returns to `accepting` once you stop it. To feel the
difference a defense makes, restart it with `--header-timeout 5`: the server reaps
slow clients (`reaped:` climbs) and keeps serving.

## The verdict — what actually happened to the service

You don't have to run `curl` in another terminal. The tool keeps one ordinary
client of its own alive throughout the run (the *availability probe*) and reports
what happened to it:

```
SERVICE DENIED — under slow headers (Slowloris) at 12 connections
The target stopped answering probe requests 1 s after the test began and was
unavailable for 18 s — 95% of the attack window. It answered again within 1 s of
the test stopping, which is consistent with resource exhaustion during the attack
rather than a crash.

probes: 1 served, 0 degraded, 6 denied (4.5% availability, threshold 95% -> FAIL)

not ruled out:
  - Packet loss or congestion between this host and the target could produce the
    same probe timings as server-side exhaustion.
  - Rate limiting, a WAF, or an upstream shedding this client specifically would
    look identical from here.
  - An intermediary (load balancer, CDN, reverse proxy) may have failed or held
    up rather than the origin.
  - Single run — re-run to confirm.
```

Sockets held say nothing on their own — a modern event-driven server will hold
every connection you can open and serve every real client throughout. The probe
is what separates "I opened 200 connections" from "nobody else could be served".

The outcome is one of `denied`, `degraded`, `held` or **`inconclusive`**. The last
one matters: if the target was already failing before the test started, or too few
probes landed, the tool says so instead of taking credit for an outage it did not
cause. `held` is reported just as conditionally — it is scoped to the connection
count you tested.

Tune with `-p` (seconds before a silent server counts as unavailable) and
`--probe-interval`. Turn it off with `--no-probe` if you only want the attack.

## Finding the threshold — `--capacity`

How many connections does it actually take? A normal run can't tell you: at
`-r 50` the ramp covers 100 connections between two probes, so any number would
be an artifact of ramp timing. The tool refuses to print one, and says why.

`--capacity` measures it properly — hold at a level, probe, step up:

```bash
python3 tests/mock_slow_server.py 8080 --workers 8

./build/slowhttptest-ng -u http://127.0.0.1:8080/ -c 32 -p 2 --probe-interval 1 \
    --capacity --capacity-start 4 --capacity-step 4 --capacity-hold 5
```

```
  level 4: 5/5 probes served, median 0 ms -> held
  level 8: 0/2 probes served, median -1 ms -> DENIED
denial threshold: 4 < n <= 8 connections (step 4)
```

Always a bracket, never a point estimate: the resolution is the step size, and
claiming better would be inventing precision.

## Reports — `-g`

```bash
./build/slowhttptest-ng -u http://127.0.0.1:8080/ -c 200 -l 120 -g -o report
```

Writes `report.html` and `report.json` from the same internal event log, so the
two cannot disagree.

The HTML is **fully self-contained** — inline CSS, inline SVG, inline data. It
opens offline, inside a container and on an air-gapped network, which the classic
report (which fetches Google Chart Tools at view time) does not. The design is
checked in at [docs/report-preview.html](docs/report-preview.html).

The JSON is for CI:

```json
{
  "result":    { "outcome": "denied", "availability": 0.0448 },
  "criterion": { "availability_threshold": 0.95, "pass": false },
  "denial_threshold": { "measured": false, "note": "not measured: ..." },
  "not_ruled_out": [ "Packet loss or congestion ...", "..." ]
}
```

Gate on `.criterion.pass`, with the bar set by `--availability-threshold`. The
process exit code stays 0 for any completed measurement — finding a denial is a
successful test run, not a failed one.

### Status codes and the gate

A `503` is a **served response**: the server answered. Treating it as a denial
would conflate "it refused me" with "it never answered me", so the outcome never
does that. Every status seen is still reported:

```json
"result": { "outcome": "held", "availability": 1.0,
            "status_counts": { "503": 9 } }
```

If a 5xx flood *is* the thing you care about, opt into it — this moves the CI
gate and nothing else:

```bash
./build/slowhttptest-ng -u http://target/ -g -o report --fail-on-status 5xx
# outcome stays "held", availability stays 1.0, criterion.pass becomes false
```

Accepts classes (`5xx`) or exact codes (`"503,429"`).

### Running silently

`-q` (or `--quiet`, or `-v 0`) produces no console output at all — reports are
still written, and errors and the exit code still speak:

```bash
./build/slowhttptest-ng -u http://target/ -c 200 -l 120 -q -g -o report
jq -e '.criterion.pass' report.json
```

## Cancelling a run

Ctrl-C quits at once. Nothing is closed, nothing is written — no verdict, no
report. A test you abandoned has no conclusion worth recording.

One line is printed first:

```
Cancelled -- nothing written. Any pause here is the OS closing the
connections; pressing Ctrl-C again will not speed it up.
```

### If it looks like it hasn't exited

It almost certainly has. A finished process that the shell has not yet reaped
stays visible as a **zombie**, and a zombie looks alarmingly like a hang:

```
45997 ?E+  (slowhttptest-ng)
```

The parentheses mean its command line is already gone; `E` means it is past
exit; it uses no CPU; `kill -9` does nothing, because there is nothing left to
kill; and it disappears the instant its parent shell does. Check with:

```bash
lsof -p <pid> | wc -l
```

**Zero descriptors means it is a zombie** — it exited, and it holds none of the
sockets you may still see in `netstat`. Those are the kernel's to clean up and
belong to no process. `pgrep -f` will not find it either, since there is no
command line left to match.

This cost several rounds of misdiagnosis during development, so it is written
down here rather than rediscovered.

### What the tool does control

Very little, and that is deliberate. The classic tool sets only `SO_RCVBUF` and
`O_NONBLOCK` on its sockets and has run this workload for fifteen years; ng now
matches it. An earlier version here added `SO_LINGER` with a zero timeout to
force an abortive close, and it turned out to buy nothing — closing a socket
with unread data already forces RST (RFC 1122), and slow read always has unread
data by construction. Verified: with no `SO_LINGER` set anywhere, the peer still
observes RST.

The cancel handler never blocks. It sets stderr non-blocking before writing,
because a terminal that is not draining — scrolled back, flow-controlled, or a
pipe nobody reads — makes `write()` block, and a signal handler that blocks traps
the process in the one place whose entire job is to leave. The message is
best-effort; the exit is not.

Maintenance sweeps are bounded by a time budget rather than closing every
eligible connection in one pass. `close()` can block against an unresponsive
peer, and with thousands of candidates a single unbounded sweep stalls the event
loop — observed as the status line jumping from 10 s straight to 35 s, with a
profile showing every sample inside `close()`.

`--connect-timeout` and `--max-connecting` bound how many connections may sit
unestablished at once. They keep the attack applying pressure instead of
accumulating dead slots, which is worth having on its own merits.

## Pointed at the wrong scheme?

The easiest way to get a meaningless run is the right port with the wrong
scheme, because both directions look like a target that silently drops
everything. The tool recognises the two signatures and says so:

```
HINT: 449 connection(s) were accepted and then closed without sending a single
      byte back. That is what a TLS listener does when it is handed a cleartext
      request. The URL says http:// -- try https://127.0.0.1:8443/
```

```
HINT: 4 connection(s) completed TCP but not one TLS handshake finished, and none
      failed either -- they are all still waiting for a ServerHello. A cleartext
      HTTP server behaves exactly this way, because it is waiting for a blank
      line that a binary ClientHello never contains.
      The URL says https:// -- try http://127.0.0.1:8080/
```

Neither can be proven from the client side, so both are printed as hints
alongside the result rather than in place of it. The verdict in these cases is
`inconclusive`, not a finding.

## Authentication, custom headers and request bodies

`-1` (or `--header`) is repeatable, so authentication and routing can coexist —
the classic tool's single slot forced you to pick one:

```bash
./build/slowhttptest-ng -u https://api.example/v1/orders -c 200 \
  -1 "Authorization: Bearer $TOKEN" \
  -1 "X-Tenant: acme" \
  -j "session=abc123"
```

Those headers ride on **every attack request and on the availability probe**.
That matters: with host-routing or tenant headers in play, an unauthenticated
probe would be answered by a different code path than the one under attack, and
the verdict would describe the wrong endpoint.

Header values are rejected if they contain CR or LF — a value spliced into every
request is a header-injection primitive otherwise.

### User agent — the tool identifies itself

```
User-Agent: Mozilla/5.0 (compatible; slowhttptest-ng/2.0.0; +https://github.com/shekyan/slowhttptest)
```

This is a testing tool, not an attack tool, and it says so on every request —
following the same `name/version (+url)` convention well-behaved crawlers have
used for decades. Whoever is on the receiving end can look the URL up, correlate
the traffic with a scheduled test, and tell it apart from a real incident.
Disguising it by default would take that away from exactly the people the tool
exists to help.

Override it when you need to:

```bash
# say something specific
./build/slowhttptest-ng -u http://target/ -A "acme-quarterly-dr-test/2026Q3"

# present as Chrome, Firefox or Safari (one picked per run)
./build/slowhttptest-ng -u http://target/ --random-user-agent
```

`--random-user-agent` exists for one real situation: a CDN or WAF that sheds the
tool's own agent before it reaches the service, so the run measures the
bot-mitigation layer instead of the thing you meant to test. That is a narrower
question than the usual one, which is why it is opt-in. Whichever agent is used
is recorded in the report (`parameters.user_agent`), because it can legitimately
change the result.

For slow body, `-P` (or `--data`) supplies a real payload, so endpoints that
validate their input don't reject the request before the hold can bite:

```bash
# literal, or @file like curl
./build/slowhttptest-ng -B -u https://api.example/v1/orders -c 200 \
  -f application/json -P @order.json
```

`Content-Length` is raised automatically to stay above the payload — if the body
ever completed, the server would answer and the hold would end. Note the padding
that follows your payload is form-style (`&x=y`), so set `-f` to match your
content type; the request is never completed, so the server never parses it.

## https, and going through a proxy

```bash
# https, including client certificates
SSL_CERT=client.pem SSL_KEY=client.key \
  ./build/slowhttptest-ng -u https://target.example/ -c 200

# everything through a proxy (CONNECT tunnel for https, absolute-URI for http)
./build/slowhttptest-ng -u https://target.example/ -d proxy.local:3128 -c 200

# attack directly, but measure availability from a different network path
./build/slowhttptest-ng -u http://target.example/ -e probe-proxy.local:3128 -c 200
```

Certificates are **not** verified by default: refusing to test a staging host or
an appliance because it presents a self-signed certificate would block the common
case. When the probe goes through a proxy, the report says so — the proxy's own
health is part of every measurement.

## Slow read (`-X`) — the mirror image

Slow read inverts Slowloris. Instead of sending a request slowly, it sends a
*complete, valid* request for a large resource and then refuses to read the
response, advertising a tiny TCP receive window (`SO_RCVBUF`, set before
`connect`). The server's send buffer fills, its response cannot drain, and the
worker is pinned mid-`send` rather than mid-`read`.

```bash
# a server with a response too big to fit in socket buffers
python3 tests/mock_slow_server.py 8080 --workers 4 --body-bytes 2000000

./build/slowhttptest-ng -X -u http://127.0.0.1:8080/ -c 12 -w 1 -y 8 -z 5 -n 3 -l 60
```

Watch `stuck_sending:` climb to the worker count — that is flow control, not HTTP,
doing the damage.

**Why it earns its own mode:** the defense that stops Slowloris does nothing here,
because the request is complete and arrives instantly. Measured against the mock
server (4 workers, 12 attacking connections, legitimate clients):

| Server configuration | Legit clients served |
|---|---|
| no timeouts | 0/3 |
| `--header-timeout 2` (the Slowloris defense) | 0/3 — **no help** |
| `--send-timeout 2` (the slow-read defense) | 3/3 |

Both directions are locked in by `tests/e2e_attacks.py`. The transport and
reporting surface — TLS, `CONNECT`, the probe, the capacity bracket, and the
refusal to conclude from an unhealthy baseline — is locked in by
`tests/e2e_transport.py`.

> **On the advertised window:** the tool prints what the kernel actually granted,
> e.g. `requested 3 B, kernel SO_RCVBUF 8195 B`. Kernels clamp to a floor and
> typically report double the request, so the effective window is larger than
> asked for. The attack still works; the number is reported rather than assumed.

> **On what `held` counts.** A connection the server has already closed is in
> `CLOSE_WAIT` — it pins nothing and is not part of the attack. Slow read cannot
> notice that the usual way: it deliberately does not watch for readability, and
> a peer's FIN arrives as a readable event rather than a hangup. It also cannot
> drain to find the end-of-stream without undoing the attack. So the tool asks
> the TCP state machine directly, once a second, and closes any connection whose
> peer has gone.
>
> This matters because the alternative is silently overstating the attack.
> Measured in the field before the fix: **5740 of a reported 10 000** connections
> were already in `CLOSE_WAIT`, with the tool reporting `peer_closed=0`. A server
> shedding load looked identical to one being held down. Detection is per-platform
> (`TCP_CONNECTION_INFO` on macOS, `TCP_INFO` on Linux); elsewhere it is absent
> rather than wrong.

> **On slow read over https:** it works. Measured against the mock https server
> (4 workers, 12 connections, 2 MB body): all four workers end up pinned mid-send
> and the probe reports `SERVICE DENIED`.
>
> One thing to know when reading the numbers — and it is a property of TLS, not a
> difference from the classic tool, which reads exactly the same way: TLS is
> record-oriented, so asking OpenSSL for `-z` plaintext bytes makes it pull a
> whole record (up to 16 KB) out of the kernel buffer in order to decrypt it. Over
> https, `-z` therefore throttles how fast the *application* consumes plaintext,
> while the kernel receive buffer drains a record at a time. The pressure still
> lands on the server's send path; the effective granularity is a TLS record
> rather than `-z` bytes.

## The four modes, and why each is distinct

Each mode attacks a different point in the request lifecycle, and — importantly —
each is stopped by a *different* timeout. That is the practical reason to keep all
four rather than collapsing them: a server hardened against one can be wide open
to the next.

| Mode | What is withheld | Server blocks in | Defense |
|---|---|---|---|
| `-H` slow headers | the end of the headers | reading headers | header timeout |
| `-B` slow body | the body promised by `Content-Length` | reading body | **body** timeout |
| `-X` slow read | acknowledgement of the response | sending | **send** timeout |
| `-R` range | nothing — it is amplification | CPU/memory | patched since 2011 |

`tests/e2e_attacks.py` asserts exactly this, including the negative results: a
header timeout demonstrably does **not** defend against slow body or slow read,
because in both cases the request headers completed instantly.

```bash
# slow body: server waits for a body that never finishes arriving
python3 tests/mock_slow_server.py 8080 --workers 4
./build/slowhttptest-ng -B -u http://127.0.0.1:8080/ -c 12 -i 5 -s 100000 -l 60

# range: a 13 KB request naming 2002 overlapping ranges
python3 tests/mock_slow_server.py 8080 --workers 4 --body-bytes 1000000
./build/slowhttptest-ng -R -u http://127.0.0.1:8080/ -c 4 -a 5 -b 2000 -l 30
```

> **On the range attack:** CVE-2011-3192 was patched in 2011, so against a current
> server this is a regression check ("is this still vulnerable?"), not a live
> exploit. The mock server *accounts* for the memory a vulnerable server would
> commit rather than really allocating it — enough to show the amplification
> (measured: a 13 KB request against a 1 MB resource ⇒ ~2 GB committed per
> request) without putting the test machine at risk.
