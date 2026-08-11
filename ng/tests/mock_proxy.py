#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A minimal HTTP proxy, just enough to exercise slowhttptest-ng's -d and -e.

Handles the two things a proxy has to do for this tool:

  * CONNECT host:port  -- open a tunnel and blindly relay bytes both ways. This
    is the path an https target takes, and the tunnel must stay byte-exact or
    the TLS record layer inside it breaks.
  * absolute-URI requests (GET http://host:port/path HTTP/1.1) -- the form a
    plain-http request takes when it is addressed to a proxy rather than to the
    origin. It is rewritten to origin form and forwarded.

Deliberately dumb: no caching, no keep-alive to the origin, no authentication.
It is a test fixture, not a proxy anyone should deploy.

Usage:
    python3 ng/tests/mock_proxy.py [PORT] [--deny]

    --deny   refuse every CONNECT with 403, to exercise the client's handling of
             a proxy that will not tunnel.
"""
import argparse
import socket
import sys
import threading

connections = 0
lock = threading.Lock()


def read_headers(conn):
    """Read up to and including the blank line that ends the request headers."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(1)
        if not chunk:
            return None, b""
        buf += chunk
        if len(buf) > 65536:
            return None, b""
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def pipe(src, dst):
    """Relay until one side closes. Byte-exact: anything else corrupts TLS."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def split_hostport(authority, default_port):
    if b":" in authority:
        host, _, port = authority.rpartition(b":")
        return host.decode(), int(port)
    return authority.decode(), default_port


def handle(conn, deny):
    global connections
    with lock:
        connections += 1
    upstream = None
    try:
        head, leftover = read_headers(conn)
        if not head:
            return
        request_line = head.split(b"\r\n", 1)[0]
        parts = request_line.split()
        if len(parts) < 3:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        method, target = parts[0], parts[1]

        if method == b"CONNECT":
            if deny:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return
            host, port = split_hostport(target, 443)
            upstream = socket.create_connection((host, port), timeout=10)
            upstream.settimeout(None)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            # Whatever the client pipelined after CONNECT is already tunnel data.
            if leftover:
                upstream.sendall(leftover)
            t = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
            t.start()
            pipe(conn, upstream)
            t.join()
            return

        # Absolute-URI form: strip scheme://authority, forward the rest.
        if not target.lower().startswith(b"http://"):
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        rest = target[len(b"http://"):]
        authority, slash, path = rest.partition(b"/")
        path = (b"/" + path) if slash else b"/"
        host, port = split_hostport(authority, 80)

        upstream = socket.create_connection((host, port), timeout=10)
        upstream.settimeout(None)
        rebuilt = b" ".join([method, path, parts[2]])
        tail = head.split(b"\r\n", 1)[1] if b"\r\n" in head else b""
        upstream.sendall(rebuilt + b"\r\n" + tail + b"\r\n\r\n")
        if leftover:
            upstream.sendall(leftover)
        t = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
        t.start()
        pipe(conn, upstream)
        t.join()
    except OSError:
        pass
    finally:
        with lock:
            connections -= 1
        for s in (conn, upstream):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", type=int, default=8888)
    ap.add_argument("--deny", action="store_true",
                    help="refuse every CONNECT with 403")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(256)
    print(f"mock proxy on 127.0.0.1:{args.port}"
          f"{' (denying CONNECT)' if args.deny else ''}", flush=True)

    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn, args.deny),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\nshutting down", file=sys.stderr)
        srv.close()


if __name__ == "__main__":
    main()
