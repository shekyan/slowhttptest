# slowhttptest-ng (M0 scaffold)

A ground-up, modern C++17 rewrite of slowhttptest. This `ng/` tree lives alongside
the original `src/` and does **not** touch it; the old tool keeps building until the
rewrite reaches feature parity.

> ⚠️ slowhttptest is an active application-layer DoS testing tool. Only run it
> against systems you are authorized to test.

## What M0 delivers (this milestone)

A **compiling, runnable vertical slice** proving the architecture end-to-end:

- **Library + CLI split** — `libslowhttp` (engine) is independent of `cli/` and
  unit-testable.
- **Reactor abstraction** (`slowhttp/reactor.hpp`) with a portable `poll()` backend
  that builds on Linux/macOS/BSD. epoll/kqueue backends drop in behind the same
  interface in M1.
- **Attack state-machine interface** (`slowhttp/attack.hpp`) — attacks decide *what
  bytes to dribble and when*; the engine owns all I/O and timers.
- **All four attack modes**, each wired end-to-end against a real target:
  slow headers (`-H`), slow body (`-B`), slow read (`-X`), range (`-R`).
- **Backward-compatible CLI flags**
  (`-H -B -R -X -u -c -r -l -i -x -s -t -f -m -j -1 -v -n -z -w -y -k -a -b -h`).
- **CMake** build, a unit test, and a smoke test (`ctest`).
- A **deliberately vulnerable mock server** (`tests/mock_slow_server.py`) with a
  fixed worker pool, so you can watch a real denial of service — not just held
  sockets.

## Not in M0 (planned, see DESIGN.md)

- TLS (https) — plain HTTP only for now; https is rejected with a clear message.
- Proxy support (`-d`, `-e`) and the availability probe (`-p`).
- epoll/kqueue backends, CSV/HTML/JSON reporting, HTTP/2 attacks.

## Build

```bash
cd ng
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Produces `ng/build/slowhttptest-ng`.

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

Both directions are locked in by `tests/e2e_slowloris.py`.

> **On the advertised window:** the tool prints what the kernel actually granted,
> e.g. `requested 3 B, kernel SO_RCVBUF 8195 B`. Kernels clamp to a floor and
> typically report double the request, so the effective window is larger than
> asked for. The attack still works; the number is reported rather than assumed.

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
