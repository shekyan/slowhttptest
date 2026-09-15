#!/usr/bin/env python3
"""End-to-end checks for --slow-quic.

What is being pinned down is the verdict: the three answers a QUIC server can
give have to come out of the tool as three different statements, because they
mean three different things about the target's defenses. Retry means no state
was created at all; an Initial alone means the packet was taken and is being
held; a Handshake means the key exchange and the certificate signature ran.
"""
import os
import subprocess
import sys
import time

TOOL = sys.argv[1]
MOCK = sys.argv[2]
SCALE = float(os.environ.get("SLOWHTTP_TEST_TIMEOUT_SCALE", "1"))

failures = []


def ok(name, detail=""):
    print("  %s: OK%s" % (name, (" (%s)" % detail) if detail else ""), flush=True)


def fail(name, why):
    print("  %s: FAIL - %s" % (name, why), flush=True)
    failures.append(name)


def free_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run_tool(args, timeout=90):
    p = subprocess.run([TOOL] + args, capture_output=True, text=True,
                       timeout=timeout * SCALE)
    return p.returncode, p.stderr + p.stdout


def case(name, mock_flag, expect, port):
    server = subprocess.Popen([sys.executable, MOCK, str(port), mock_flag],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        _, out = run_tool(["--slow-quic", "-u", "https://127.0.0.1:%d/" % port,
                           "-c", "4", "-i", "2", "-l", "8", "-p", "9"])
        line = ""
        for ln in out.splitlines():
            if ln.startswith("QUIC:"):
                line = ln
                break
        if not line:
            return fail(name, "no QUIC summary line at all: %s" % out[-300:])
        if expect not in line:
            return fail(name, "expected %r in: %s" % (expect, line))
        ok(name, line[6:60].strip())
    finally:
        server.terminate()
        server.wait()


def main():
    # A server doing address validation. The point of the mode is to tell this
    # apart from a server that holds -- reporting a hold here would be the
    # worst possible failure, since it is the mitigation working.
    case("quic retry", "--retry", "answered with Retry", free_port())
    # Took the packet, produced nothing.
    case("quic held", "--ack", "accepted and held", free_port())
    # Ran the expensive half.
    case("quic handshake flight", "--flight", "got a Handshake flight", free_port())
    # Nothing there at all must not read as a successful hold.
    case("quic silent", "--silent", "never answered", free_port())

    # Nothing listening is a different failure again, and must not be silent.
    _, out = run_tool(["--slow-quic", "-u", "https://127.0.0.1:%d/" % free_port(),
                       "-c", "2", "-i", "2", "-l", "6", "-p", "9"])
    if "never answered" not in out:
        fail("quic dead port", "a closed port did not read as unanswered")
    else:
        ok("quic dead port")

    # A flag that selects no mode must not be accepted and dropped: this exact
    # invocation once ran slow headers over TCP while reading as a QUIC test.
    rc, out = run_tool(["--quic-hello", "partial", "-u", "https://127.0.0.1:443/",
                        "-c", "2", "-l", "2"], timeout=30)
    if rc == 0:
        fail("quic-hello needs slow-quic", "it was accepted without --slow-quic")
    elif "needs --slow-quic" not in out:
        fail("quic-hello needs slow-quic", "no explanation: %r" % out[:200])
    elif "Did you mean" not in out or "--slow-quic --quic-hello partial" not in out:
        fail("quic-hello needs slow-quic",
             "refused, but without showing the fix: %r" % out[:300])
    else:
        ok("quic-hello needs slow-quic", "and the hint shows the corrected flags")

    # An http:// URL has no QUIC to speak to and must be refused up front.
    rc, out = run_tool(["--slow-quic", "-u", "http://127.0.0.1:80/", "-l", "2"],
                       timeout=30)
    if rc == 0 or "needs an https:// URL" not in out:
        fail("quic refuses http", "rc=%s out=%r" % (rc, out[:200]))
    else:
        ok("quic refuses http")

    if failures:
        print("FAILED: %s" % ", ".join(failures))
        return 1
    print("all quic e2e checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
