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
import re
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


def tls_supported(tool):
    """Whether this build can speak https at all.

    The no-TLS build refuses https targets at startup, which is its documented
    behaviour and not a CLI-parsing conflict, so the one case below that needs
    an https URL has to know the difference.
    """
    r = subprocess.run([tool, "-u", "https://127.0.0.1:1/", "-c", "1",
                        "-l", "1", "--no-probe"],
                       capture_output=True, text=True, timeout=30)
    return "no TLS backend" not in (r.stdout + r.stderr)


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

    # HTTP/2 through a plain-http proxy has to be refused, not attempted.
    # Attempted, it produces a run that looks like a result: the proxy cannot
    # parse an HTTP/2 preface, closes every connection, and the tool reports a
    # pile of peer closes and "No open connections left" -- indistinguishable
    # from a target shedding load. Measured before the check existed: 24
    # connections opened, 24 closed by the proxy, nothing tested.
    r = subprocess.run([tool, "-X", "--http2", "-u", "http://127.0.0.1:1/",
                        "-d", "127.0.0.1:2", "-c", "1", "-l", "1"],
                       capture_output=True, text=True, timeout=30)
    combined = (r.stdout + r.stderr).lower()
    if r.returncode == 0:
        fail("refuses http2 through an http proxy", "it was accepted")
    elif "--http2" not in combined or "-d" not in combined:
        fail("refuses http2 through an http proxy",
             "rejected without naming the conflict: %s" % r.stderr[-200:])
    else:
        ok("refuses http2 through an http proxy")

    # ...but https through a CONNECT tunnel is fine and must stay allowed, so
    # the check above cannot simply ban --http2 alongside -d. This one is
    # expected to fail at connect time, not at argument parsing.
    #
    # Skipped on a build with no TLS backend: refusing https there is the
    # documented behaviour of that configuration rather than a parsing
    # conflict, so exit code 2 would be correct and tell us nothing.
    if tls_supported(tool):
        r = subprocess.run([tool, "-X", "--http2", "-u", "https://127.0.0.1:1/",
                            "-d", "127.0.0.1:2", "-c", "1", "-l", "1",
                            "--no-probe", "-q"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 2:
            fail("allows http2 through a CONNECT proxy",
                 "rejected as a usage error: %s" % (r.stdout + r.stderr)[-200:])
        else:
            ok("allows http2 through a CONNECT proxy")
    else:
        print("  allows http2 through a CONNECT proxy: "
              "skipped (no TLS backend in this build)", flush=True)

    # -4 and -6 shipped with no coverage at all. They decide which network a
    # run measures, and a run that silently lands on the other one disagrees
    # with its predecessor for reasons nothing in the output explains.
    port = free_port(9900)
    srv = subprocess.Popen([sys.executable, mock, str(port), "--seconds", "12"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    try:
        r = subprocess.run([tool, "-X", "-4", "-u", "http://localhost:%d/" % port,
                            "-c", "2", "-r", "2", "-l", "3", "--no-probe"],
                           capture_output=True, text=True, timeout=60)
        if "127.0.0.1" not in r.stderr:
            fail("-4 pins IPv4", "did not resolve to an IPv4 address:\n%s"
                 % r.stderr[-300:])
        else:
            ok("-4 pins IPv4")

        # The mock listens on IPv4 only, so -6 must fail cleanly and say that
        # nothing was tested -- never report a result it did not measure.
        r = subprocess.run([tool, "-X", "-6", "-u", "http://localhost:%d/" % port,
                            "-c", "2", "-r", "2", "-l", "3", "--no-probe"],
                           capture_output=True, text=True, timeout=60)
        both = r.stdout + r.stderr
        if r.returncode == 0:
            fail("-6 pins IPv6", "exited 0 despite reaching nothing")
        elif "::1" not in both and "no IPv6" not in both:
            fail("-6 pins IPv6", "did not resolve to IPv6:\n%s" % both[-300:])
        elif "nothing was actually tested" not in both:
            fail("-6 pins IPv6", "failed without saying nothing was tested")
        else:
            ok("-6 pins IPv6", "and says nothing was tested")
    finally:
        srv.kill()

    # The probe must reach the same address the attack does.
    #
    # It used to resolve the target independently, so against a dual-stack name
    # the attack could pin ::1 -- where nothing listened, every connection
    # refused -- while the probe reached 127.0.0.1 and reported the service
    # healthy. The probe is the oracle every verdict rests on, so that is a run
    # measuring one machine and reporting on another; on a real target it would
    # be silently wrong rather than visibly broken.
    #
    # Asserted against the reported endpoints rather than against the symptom.
    # Waiting for the symptom means waiting for the two resolutions to disagree,
    # which depends on resolver ordering -- the unstable thing this is about --
    # and a first attempt at that passed against the reintroduced bug by luck.
    port = free_port(9950)
    srv = subprocess.Popen([sys.executable, mock, str(port), "--seconds", "20"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    try:
        pairs = []
        for fam in ("-4", "-6"):
            r = subprocess.run([tool, "-X", fam,
                                "-u", "http://localhost:%d/" % port,
                                "-c", "2", "-r", "2", "-l", "3",
                                "-p", "2", "--probe-interval", "1"],
                               capture_output=True, text=True, timeout=90)
            both = r.stdout + r.stderr
            attack = re.search(r"resolved address:\s+(\S+)", both)
            probe = re.search(r"probe endpoint:\s+(\S+)", both)
            pairs.append((fam, attack.group(1) if attack else None,
                          probe.group(1) if probe else None))

        bad = [p for p in pairs if p[1] is None or p[2] is None or p[1] != p[2]]
        if bad:
            fail("probe follows the attack",
                 "attack and probe endpoints differ: %s" % bad)
        else:
            # And -4/-6 must actually move it, or both could agree by accident
            # on whatever the resolver happened to prefer.
            fams = {p[0]: p[1] for p in pairs}
            if fams["-4"] == fams["-6"]:
                fail("probe follows the attack",
                     "-4 and -6 chose the same address: %s" % fams)
            else:
                ok("probe follows the attack",
                   "%s and %s, probe matched both" % (fams["-4"], fams["-6"]))
    finally:
        srv.kill()

    if failures:
        print("e2e: %d case(s) failed: %s" % (len(failures), ", ".join(failures)),
              flush=True)
        return 1
    print("e2e: http2 framing all passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
