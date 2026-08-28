#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A minimal HTTP/2 listener that checks what a client actually sent.

Not a server -- it never answers. It exists because a framing bug is invisible
from the client side: a real server that dislikes our frames simply closes or
goes quiet, which is indistinguishable from a slow-read attack working. So this
parses the preface and every frame, and reports what it saw.

Usage:
    python3 mock_h2_server.py [PORT] [--expect-streams N] [--seconds S]

Exits non-zero if the client's opening burst is not well-formed HTTP/2.
"""
import argparse
import socket
import struct
import sys
import time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
         5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
         9: "CONTINUATION"}
SETTING_NAMES = {1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH",
                 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE",
                 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE"}


def hpack_literals(block):
    """Decode only what this tool emits: literal, no indexing, new name.

    Anything else means the encoder changed and this check no longer proves
    what it claims, so it says so rather than guessing.
    """
    out, i = [], 0
    while i < len(block):
        if block[i] != 0x00:
            raise ValueError("byte %d is 0x%02x, not a literal-without-indexing"
                             " prefix" % (i, block[i]))
        i += 1
        vals = []
        for _ in range(2):
            if block[i] & 0x80:
                raise ValueError("Huffman-coded string at %d" % i)
            n = block[i] & 0x7f
            i += 1
            if n == 0x7f:
                shift, n = 0, 0x7f
                while True:
                    b = block[i]
                    i += 1
                    n += (b & 0x7f) << shift
                    shift += 7
                    if not b & 0x80:
                        break
            vals.append(block[i:i + n].decode("utf-8", "replace"))
            i += n
        out.append((vals[0], vals[1]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", type=int, default=8443)
    ap.add_argument("--expect-streams", type=int, default=0)
    ap.add_argument("--expect-resets", type=int, default=0)
    ap.add_argument("--expect-continuations", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=10.0)
    args = ap.parse_args()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(64)
    srv.settimeout(args.seconds)
    print("h2 check listening on %d" % args.port, flush=True)

    try:
        conn, _ = srv.accept()
    except socket.timeout:
        print("FAIL: nothing connected", flush=True)
        return 1
    conn.settimeout(args.seconds)

    buf = b""
    deadline = time.time() + args.seconds
    while len(buf) < len(PREFACE) and time.time() < deadline:
        try:
            d = conn.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf += d

    if not buf.startswith(PREFACE):
        print("FAIL: bad preface: %r" % buf[:32], flush=True)
        return 1
    print("ok: connection preface", flush=True)
    buf = buf[len(PREFACE):]

    frames, streams, problems = [], set(), []
    resets = []          # stream ids cancelled, in order
    continuations = 0
    end_headers_seen = False
    order = []           # (kind, stream id) for HEADERS and RST_STREAM only
    while time.time() < deadline:
        while len(buf) >= 9:
            length, = struct.unpack(">I", b"\0" + buf[:3])
            ftype, flags = buf[3], buf[4]
            sid, = struct.unpack(">I", buf[5:9])
            if sid & 0x80000000:
                problems.append("reserved bit set in stream id")
            sid &= 0x7fffffff
            if len(buf) < 9 + length:
                break
            payload = buf[9:9 + length]
            buf = buf[9 + length:]
            name = TYPES.get(ftype, "UNKNOWN(%d)" % ftype)
            frames.append(name)

            if name == "SETTINGS":
                if length % 6:
                    problems.append("SETTINGS payload %d not a multiple of 6"
                                    % length)
                for off in range(0, length, 6):
                    ident, val = struct.unpack(">HI", payload[off:off + 6])
                    print("   SETTINGS %s = %d"
                          % (SETTING_NAMES.get(ident, ident), val), flush=True)
                    if ident == 4 and val > 0x7fffffff:
                        problems.append("INITIAL_WINDOW_SIZE above 2^31-1")
            elif name == "WINDOW_UPDATE":
                inc, = struct.unpack(">I", payload)
                inc &= 0x7fffffff
                print("   WINDOW_UPDATE stream %d += %d" % (sid, inc),
                      flush=True)
                if inc == 0:
                    problems.append("WINDOW_UPDATE increment of 0")
            elif name == "CONTINUATION":
                continuations += 1
                if flags & 0x4:
                    end_headers_seen = True
            elif name == "RST_STREAM":
                code, = struct.unpack(">I", payload) if length == 4 else (None,)
                if length != 4:
                    problems.append("RST_STREAM payload %d bytes, want 4"
                                    % length)
                resets.append(sid)
                order.append(("RST", sid))
            elif name == "HEADERS":
                if flags & 0x4:
                    end_headers_seen = True
                order.append(("HDR", sid))
                streams.add(sid)
                if sid % 2 == 0:
                    problems.append("client used even stream id %d" % sid)
                if len(streams) == 1:
                    try:
                        hdrs = hpack_literals(payload)
                    except ValueError as e:
                        problems.append("HPACK: %s" % e)
                    else:
                        names = [h[0] for h in hdrs]
                        print("   HEADERS stream %d: %s" % (sid, names),
                              flush=True)
                        pseudo = [n for n in names if n.startswith(":")]
                        if pseudo != [":method", ":scheme", ":authority",
                                      ":path"]:
                            problems.append("pseudo-headers wrong or misordered:"
                                            " %s" % pseudo)
                        if names[:len(pseudo)] != pseudo:
                            problems.append("pseudo-headers not first")
                        for n in names:
                            if n != n.lower():
                                problems.append("uppercase header %r" % n)
        try:
            d = conn.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf += d

    print("frames: %s" % ", ".join(frames[:6] +
          (["..."] if len(frames) > 6 else [])), flush=True)
    print("streams opened: %d" % len(streams), flush=True)
    if args.expect_resets:
        print("streams reset: %d" % len(resets), flush=True)
        if len(resets) < args.expect_resets:
            problems.append("expected at least %d resets, saw %d"
                            % (args.expect_resets, len(resets)))
        # Every reset must immediately follow the HEADERS for the same stream.
        # A reset that lags behind, or names a different stream, is a different
        # attack and would not exercise the accounting defect at all.
        for i in range(0, min(len(order) - 1, 40), 2):
            kind_a, id_a = order[i]
            kind_b, id_b = order[i + 1]
            if kind_a != "HDR" or kind_b != "RST" or id_a != id_b:
                problems.append("frame %d/%d is %s(%d),%s(%d), want HEADERS then"
                                " RST_STREAM on the same stream"
                                % (i, i + 1, kind_a, id_a, kind_b, id_b))
                break

    if args.expect_continuations:
        print("continuations: %d" % continuations, flush=True)
        if continuations < args.expect_continuations:
            problems.append("expected at least %d CONTINUATION frames, saw %d"
                            % (args.expect_continuations, continuations))
        # The whole attack is that the block is never completed. One END_HEADERS
        # anywhere hands the server a well-formed request and turns this into an
        # ordinary slow client, so it is the single thing worth asserting.
        if end_headers_seen:
            problems.append("END_HEADERS was set: the header block was closed,"
                            " which is not this attack")
        # And nothing may be interleaved between HEADERS and its CONTINUATIONs
        # (RFC 7540 6.2). A server is entitled to treat that as a connection
        # error, so getting it wrong would end the run rather than sustain it.
        after_headers = frames[frames.index("HEADERS") + 1:] \
            if "HEADERS" in frames else []
        stray = [f for f in after_headers if f != "CONTINUATION"]
        if stray:
            problems.append("frames interleaved into the header block: %s"
                            % ", ".join(sorted(set(stray))))

    if args.expect_streams and len(streams) != args.expect_streams:
        problems.append("expected %d streams, saw %d"
                        % (args.expect_streams, len(streams)))
    if buf:
        problems.append("%d trailing bytes did not form a frame" % len(buf))

    for p in problems:
        print("FAIL: %s" % p, flush=True)
    print("h2 check: %s" % ("PASS" if not problems else "FAIL"), flush=True)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
