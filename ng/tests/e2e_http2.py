#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""End-to-end check that --http2 puts valid HTTP/2 on the wire.

The unit test proves the encoder emits the bytes the RFC describes. This proves
the attack assembles them into something a peer accepts as a connection: the
preface, then settings that open the application window, then one stream per
--h2-streams. A framing mistake here is silent against a real server -- it
closes or goes quiet, which is what a working slow-read attack also looks like.

    usage: e2e_http2.py <slowhttptest-ng> <mock_h2_server.py>
"""
import os
import subprocess
import sys
import time

failures = []


def ok(name, detail=""):
    print("  %s: OK%s" % (name, (" (%s)" % detail) if detail else ""), flush=True)


def fail(name, why):
    print("  %s: FAIL - %s" % (name, why), flush=True)
    failures.append(name)


def free_port(base):
    import socket
    for p in range(base, base + 200):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free port")


def run_case(tool, mock, streams):
    port = free_port(9300)
    checker = subprocess.Popen(
        [sys.executable, mock, str(port), "--expect-streams", str(streams),
         "--seconds", "15"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.0)
    ng = subprocess.run(
        [tool, "-X", "--http2", "--h2-streams", str(streams),
         "-u", "http://127.0.0.1:%d/" % port,
         "-c", "1", "-r", "1", "-l", "4", "--no-probe", "-q"],
        capture_output=True, text=True, timeout=60)
    out, _ = checker.communicate(timeout=40)
    return checker.returncode, out, ng


def run_reset(tool, mock, rate, seconds):
    port = free_port(9500)
    checker = subprocess.Popen(
        [sys.executable, mock, str(port), "--expect-resets",
         str(max(1, rate * (seconds - 2))), "--seconds", str(seconds + 6)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.0)
    subprocess.run(
        [tool, "--rapid-reset", "-u", "http://127.0.0.1:%d/" % port,
         "-c", "1", "-r", "1", "-l", str(seconds),
         "--h2-reset-rate", str(rate), "--no-probe", "-q"],
        capture_output=True, text=True, timeout=90)
    out, _ = checker.communicate(timeout=40)
    return checker.returncode, out


def run_continuation(tool, mock, seconds):
    port = free_port(9700)
    checker = subprocess.Popen(
        [sys.executable, mock, str(port), "--expect-continuations", "2",
         "--seconds", str(seconds + 6)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.0)
    subprocess.run(
        [tool, "--continuation-flood", "-u", "http://127.0.0.1:%d/" % port,
         "-c", "1", "-r", "1", "-l", str(seconds), "-i", "1",
         "--no-probe", "-q"],
        capture_output=True, text=True, timeout=90)
    out, _ = checker.communicate(timeout=40)
    return checker.returncode, out


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    tool, mock = sys.argv[1], sys.argv[2]

    print("e2e: http2 framing", flush=True)

    # One stream: the simplest well-formed HTTP/2 conversation this tool can have.
    rc, out, ng = run_case(tool, mock, 1)
    if rc != 0:
        fail("single stream", "checker rejected the framing:\n%s" % out)
    elif "ok: connection preface" not in out:
        fail("single stream", "no preface seen")
    else:
        ok("single stream")

    # Many streams on one connection: the property that makes this attack evade
    # per-IP connection limits, so it is worth asserting rather than assuming.
    rc, out, ng = run_case(tool, mock, 32)
    if rc != 0:
        fail("multiplexed streams", "checker rejected the framing:\n%s" % out)
    elif "streams opened: 32" not in out:
        fail("multiplexed streams", "wrong stream count:\n%s" % out)
    else:
        ok("multiplexed streams", "32 streams on one connection")

    # The window has to be opened explicitly, or the connection caps at 64 KB
    # and the attack stops meaning anything after the first response.
    if "INITIAL_WINDOW_SIZE = 2147483647" not in out:
        fail("windows opened", "stream window not opened to the maximum")
    elif "WINDOW_UPDATE stream 0" not in out:
        fail("windows opened", "connection window never opened")
    else:
        ok("windows opened", "stream and connection windows both at maximum")

    # --http2 is only implemented for slow read; the others must say so rather
    # than quietly sending HTTP/1.1 and reporting a result that means nothing.
    r = subprocess.run([tool, "-H", "--http2", "-u", "http://127.0.0.1:1/",
                        "-c", "1", "-l", "1"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        fail("refuses unsupported modes", "accepted --http2 with -H")
    elif "http2" not in (r.stderr + r.stdout).lower():
        fail("refuses unsupported modes",
             "rejected it without saying why: %s" % r.stderr[-200:])
    else:
        ok("refuses unsupported modes")

    # Rapid reset: the frames have to be HEADERS immediately followed by
    # RST_STREAM on the same stream, at roughly the requested rate. The checker
    # asserts the pairing; anything else is a different attack wearing the name.
    rc, out = run_reset(tool, mock, 50, 4)
    if rc != 0:
        fail("rapid reset", "checker rejected the frames:\n%s" % out)
    elif "streams reset:" not in out:
        fail("rapid reset", "no resets seen:\n%s" % out)
    else:
        seen = [l for l in out.splitlines() if l.startswith("streams reset:")]
        ok("rapid reset", seen[0] if seen else "")

    # CONTINUATION flood: a header block that is opened and never closed.
    # The checker asserts no END_HEADERS ever arrives and that nothing is
    # interleaved -- either would make it a different, well-formed conversation.
    rc, out = run_continuation(tool, mock, 6)
    if rc != 0:
        fail("continuation flood", "checker rejected the frames:\n%s" % out)
    elif "continuations:" not in out:
        fail("continuation flood", "no CONTINUATION frames seen:\n%s" % out)
    else:
        seen = [l for l in out.splitlines() if l.startswith("continuations:")]
        ok("continuation flood", seen[0] if seen else "")

    if failures:
        print("e2e: %d case(s) failed: %s" % (len(failures), ", ".join(failures)),
              flush=True)
        return 1
    print("e2e: http2 framing all passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
