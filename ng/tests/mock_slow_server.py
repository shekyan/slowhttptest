#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A deliberately vulnerable HTTP server for demoing slow-header attacks locally.

Unlike a trivial connection counter, this models what actually makes Slowloris
work: a server with a FIXED worker pool and NO timeout on reading request headers.
Each worker accepts a connection, reads the request headers to completion, serves a
small page, then goes back to accepting. A slow client that never finishes its
headers pins a worker forever -- once every worker is pinned, legitimate clients
can no longer be served. That is the denial of service.

It models both slow-attack families, which exploit opposite ends of the same
request lifecycle:
  * slow headers -- a worker blocks *reading* a request that never ends
  * slow read    -- a worker blocks *sending* a response the client won't accept
Each has its own timeout knob, because in real servers they are separate settings
and defending one does nothing for the other.

Usage:
    python3 ng/tests/mock_slow_server.py [PORT] [--workers N] [--header-timeout S]
                                         [--send-timeout S] [--body-bytes N]

    PORT               listen port (default 8080)
    --workers N        size of the worker pool (default 8)
    --header-timeout S  seconds a worker waits for complete headers before giving
                        up. Omit (the default) for the VULNERABLE behavior; set it
                        (e.g. 5) to model a MITIGATED server that reaps slow clients.

A header timeout is a partial defense, not a cure, for a thread-per-connection
server: reaped attackers simply reconnect and keep competing for the freed
workers, so legitimate clients still see degraded latency. The difference is that
the server keeps making progress instead of being wedged at zero served requests.
Fully defeating this needs an event-driven server (or per-IP connection limits) so
that a held connection does not own a worker.

Demo:
    # vulnerable server, 8 workers
    python3 ng/tests/mock_slow_server.py 8080 --workers 8

    curl -s --max-time 3 http://127.0.0.1:8080/         # -> 200 OK (healthy)
    ./build/slowhttptest-ng -u http://127.0.0.1:8080/ -c 20 -i 5 -l 120 &
    curl -s --max-time 3 http://127.0.0.1:8080/ || echo DENIED   # -> DENIED

Authorized local testing only.
"""
import argparse
import socket
import ssl
import threading
import time

def build_response(body_bytes):
    body = (b"hello from the vulnerable server\n"
            if body_bytes <= 0 else b"A" * body_bytes)
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )


busy = 0            # workers currently reading a request
served = 0          # requests answered fully (response flushed to the client)
reaped = 0          # slow clients dropped (only with --header-timeout)
stuck = 0           # workers blocked mid-send because the client won't read
range_bytes = 0     # simulated memory a vulnerable server would commit to ranges
lock = threading.Lock()


def read_headers(conn, header_timeout):
    """Read until the blank line that ends HTTP headers.

    Returns (ok, headers_bytes, leftover_body_bytes). ok is False if the client
    was too slow (only possible when a timeout is set).
    """
    conn.settimeout(header_timeout)  # None => block forever (vulnerable)
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            return False, buf, b""
        if not chunk:
            return False, buf, b""  # client closed before finishing
        buf += chunk
        if len(buf) > 8 << 20:
            return False, buf, b""  # absurdly large headers; bail
    head, _, rest = buf.partition(b"\r\n\r\n")
    return True, head, rest


def content_length(head):
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def count_ranges(head):
    """Number of byte-range specs requested, or 0 if there is no Range header."""
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"range:"):
            spec = line.split(b":", 1)[1].strip()
            spec = spec.split(b"=", 1)[1] if b"=" in spec else spec
            return len([p for p in spec.split(b",") if p.strip()])
    return 0


def read_body(conn, need, already, body_timeout):
    """Consume `need` bytes of request body. This is where slow body bites: the
    Content-Length header promised bytes the client dribbles a few at a time, and
    a server without a body timeout waits for all of them."""
    conn.settimeout(body_timeout)  # None => block forever (vulnerable)
    got = len(already)
    while got < need:
        try:
            chunk = conn.recv(min(65536, need - got))
        except socket.timeout:
            return False
        if not chunk:
            return False
        got += len(chunk)
    return True


def worker(srv, cfg, response, tls_ctx=None):
    global busy, served, reaped, stuck, range_bytes
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with lock:
            busy += 1
        if tls_ctx is not None:
            # The handshake runs on the worker, as it does on a real
            # thread-per-connection server -- so a client that stalls mid
            # handshake pins a worker just like one that stalls mid request.
            try:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                with lock:
                    busy -= 1
                    reaped += 1
                try:
                    conn.close()
                except OSError:
                    pass
                continue
        blocked = False
        try:
            ok, head, rest = read_headers(conn, cfg.header_timeout)
            if ok:
                need = content_length(head)
                if need > 0:
                    ok = read_body(conn, need, rest, cfg.body_timeout)

            if ok:
                # Range amplification: a vulnerable server buffers (and gzips) a
                # copy of the resource per requested range. We only ACCOUNT for
                # that here rather than really allocating it -- the point is to
                # show the amplification factor, not to OOM the test machine.
                n_ranges = count_ranges(head)
                if n_ranges > 1:
                    with lock:
                        range_bytes += n_ranges * len(response)

                # This sendall is where slow read bites: with a tiny client window
                # the kernel send buffer fills, sendall blocks, and this worker is
                # pinned here for as long as the client refuses to read.
                with lock:
                    stuck += 1
                blocked = True
                conn.settimeout(cfg.send_timeout)  # None => block (vulnerable)
                conn.sendall(response)
                with lock:
                    stuck -= 1
                    blocked = False
                    served += 1
            else:
                with lock:
                    reaped += 1
        except OSError:
            # Includes socket.timeout from a send timeout: the client was reaped
            # for not reading its response.
            if blocked:
                with lock:
                    stuck -= 1
                    reaped += 1
        finally:
            with lock:
                busy -= 1
            try:
                conn.close()
            except OSError:
                pass


def reporter(workers):
    while True:
        with lock:
            b, s, r, k, rb = busy, served, reaped, stuck, range_bytes
        state = "SATURATED - denying new clients" if b >= workers else "accepting"
        extra = f"  range_committed: {rb / 1e6:.1f}MB" if rb else ""
        print(f"workers busy: {b}/{workers}  served: {s}  reaped: {r}  "
              f"stuck_sending: {k}{extra}  [{state}]", flush=True)
        time.sleep(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", type=int, default=8080)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--header-timeout", type=float, default=None)
    ap.add_argument("--body-timeout", type=float, default=None,
                    help="seconds to wait for the request body promised by "
                         "Content-Length; omit for the VULNERABLE behavior. "
                         "This is the defense against slow body, and a header "
                         "timeout does nothing for it.")
    ap.add_argument("--send-timeout", type=float, default=None,
                    help="seconds to wait for a client to accept its response "
                         "before giving up; omit for the VULNERABLE behavior. "
                         "This is the defense against slow read, and is a "
                         "separate setting from --header-timeout.")
    ap.add_argument("--body-bytes", type=int, default=0,
                    help="response body size; use a large value (e.g. 1000000) "
                         "to demo slow read, which needs a response too big to "
                         "fit in the socket buffers")
    ap.add_argument("--tls-cert", default=None,
                    help="PEM certificate; serves https when given with --tls-key")
    ap.add_argument("--tls-key", default=None, help="PEM private key")
    args = ap.parse_args()
    response = build_response(args.body_bytes)

    tls_ctx = None
    if bool(args.tls_cert) != bool(args.tls_key):
        ap.error("--tls-cert and --tls-key must be given together")
    if args.tls_cert:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(args.tls_cert, args.tls_key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(128)

    defenses = []
    if args.header_timeout is not None:
        defenses.append(f"header timeout {args.header_timeout}s")
    if args.body_timeout is not None:
        defenses.append(f"body timeout {args.body_timeout}s")
    if args.send_timeout is not None:
        defenses.append(f"send timeout {args.send_timeout}s")
    mode = "VULNERABLE (no timeouts)" if not defenses else \
        "mitigated (" + ", ".join(defenses) + ")"
    scheme = "HTTPS" if tls_ctx else "HTTP"
    print(f"mock {scheme} server on 0.0.0.0:{args.port}  workers={args.workers}  "
          f"body={len(response)}B  mode={mode}")

    for _ in range(args.workers):
        threading.Thread(target=worker, args=(srv, args, response, tls_ctx),
                         daemon=True).start()
    threading.Thread(target=reporter, args=(args.workers,), daemon=True).start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nshutting down")
        srv.close()


if __name__ == "__main__":
    main()
