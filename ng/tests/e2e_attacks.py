#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""End-to-end regression tests for all four attack modes.

Each attack is checked against a deliberately vulnerable local server, plus a
negative control showing the matching defense stops it. The controls matter: a bug
that made the tool send nothing at all would still "pass" a denial-only assertion,
for entirely the wrong reason.

Availability is measured by the SERVER's own counters rather than by whether one
racing client got through. With a handful of workers and many attacker
connections, any single client's success is a coin flip; the counters are not.
The crisp, non-flaky distinction is progress:

    vulnerable -> the served counter is stuck at zero
    defended   -> the served counter keeps climbing

Range is the exception: it is amplification rather than a slow hold, so it is
measured by the server-side cost it provokes per byte of request.

Usage: e2e_attacks.py <path-to-slowhttptest-ng> <path-to-mock_slow_server.py>
"""
import re
import socket
import os
import subprocess
import sys
import tempfile
import threading
import time

WORKERS = 4
COUNTER_RE = re.compile(
    r"workers busy: (\d+)/\d+\s+served: (\d+)\s+reaped: (\d+)\s+stuck_sending: (\d+)")
RANGE_RE = re.compile(r"range_committed: ([\d.]+)MB")


class Server:
    """The mock server plus a reader for the counters it prints once a second."""

    def __init__(self, mock, port, extra=()):
        self.port = port
        self._log = tempfile.NamedTemporaryFile(mode="w+", suffix=".log", delete=False)
        self.proc = subprocess.Popen(
            [sys.executable, mock, str(port), "--workers", str(WORKERS), *extra],
            stdout=self._log, stderr=subprocess.DEVNULL)

    def counters(self):
        """Latest (busy, served, reaped, stuck) the server reported, or None."""
        with open(self._log.name) as fh:
            matches = COUNTER_RE.findall(fh.read())
        if not matches:
            return None
        return tuple(int(x) for x in matches[-1])

    def range_committed_mb(self):
        """Simulated memory the server would have committed to range requests."""
        with open(self._log.name) as fh:
            matches = RANGE_RE.findall(fh.read())
        return float(matches[-1]) if matches else 0.0

    def stop(self):
        terminate(self.proc)
        self._log.close()


def http_get(port, timeout=3.0, read_all=False):
    """Returns response bytes, or None if the server could not serve us."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            if not read_all:
                return s.recv(1024) or None
            chunks = []
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks) or None
    except (OSError, socket.timeout):
        return None


def wait_until(predicate, timeout, interval=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def free_port():
    """A port nothing is listening on, asked of the kernel rather than assumed.

    These used to be fixed numbers, and that turned one failure into a run of
    them. ctest kills a timed-out harness outright, so its finally blocks never
    run and the mock servers survive; the next run then finds its port already
    open, wait_until(port_open) succeeds against the *stale* server, and the
    case talks to the wrong process. That hangs, times out, and leaks another
    server. Self-sustaining, and for days it looked like an intermittent fault
    in the tool under test.
    """
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def sweep_stale_servers():
    """Kill mock servers a previously killed run left behind."""
    import signal as _sig
    try:
        out = subprocess.run(["pgrep", "-f", "tests/mock_"],
                             capture_output=True, text=True).stdout.split()
    except OSError:
        return
    mine = str(os.getpid())
    for pid in out:
        if pid == mine:
            continue
        try:
            os.kill(int(pid), _sig.SIGKILL)
        except (OSError, ValueError):
            pass


def terminate(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def start_attack(tool, port, mode, conns, extra=()):
    return subprocess.Popen(
        [tool, mode, "-u", f"http://127.0.0.1:{port}/", "-c", str(conns),
         "-r", "50", "-l", "120", *extra],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def served_delta(server, port, seconds=6.0, patience=3.0):
    """Legit clients keep knocking for a while; returns how many the server served.

    Uses the server's counter, so a client that times out but whose request was
    eventually completed still counts as progress.

    The knocker must read the *entire* body: the server only counts a request as
    served once its sendall() finishes, so a client that grabs the first KB and
    hangs up would leave the counter flat and look identical to a denial.
    """
    before = server.counters()
    before_served = before[1] if before else 0
    stop = time.time() + seconds
    knocker = threading.Thread(
        target=lambda: [http_get(port, timeout=patience, read_all=True)
                        for _ in iter(lambda: time.time() < stop, False)],
        daemon=True)
    knocker.start()
    knocker.join(timeout=seconds + patience + 2)
    time.sleep(1.5)  # let the reporter emit a fresh line
    after = server.counters()
    return (after[1] if after else 0) - before_served


def run_case(name, tool, mock, port, mode, server_extra, attack_extra,
             expect_progress, saturation_field=None):
    """Runs one attack against one server configuration and checks availability."""
    server = attack = None
    try:
        server = Server(mock, port, server_extra)
        if not wait_until(lambda: http_get(port) is not None, timeout=10):
            raise SystemExit(f"FAIL[{name}]: server never became healthy")

        attack = start_attack(tool, port, mode, WORKERS * 3, attack_extra)
        # Give the attack time to claim the workers.
        wait_until(lambda: (server.counters() or (0,))[0] >= WORKERS, timeout=30)

        if saturation_field is not None:
            c = server.counters()
            if not c or c[saturation_field] == 0:
                raise SystemExit(
                    f"FAIL[{name}]: expected workers pinned, counters={c}")

        delta = served_delta(server, port)
        if expect_progress and delta <= 0:
            raise SystemExit(
                f"FAIL[{name}]: defended server should keep serving, delta={delta}")
        if not expect_progress and delta > 0:
            raise SystemExit(
                f"FAIL[{name}]: vulnerable server should be wedged, delta={delta}")
        print(f"  {name}: OK (served delta {delta})")
    finally:
        terminate(attack)
        if server:
            server.stop()


def run_range_case(tool, mock, port):
    """Range is not a slow hold -- it is amplification, so it is measured that way.

    A few kilobytes of Range header should drive orders of magnitude more
    server-side cost. The mock only accounts for that memory rather than really
    allocating it, so the assertion is on the ratio, not on the server falling over.
    """
    body_mb = 1.0
    server = attack = None
    try:
        server = Server(mock, port, ("--body-bytes", str(int(body_mb * 1e6))))
        if not wait_until(lambda: http_get(port, read_all=True) is not None,
                          timeout=10):
            raise SystemExit("FAIL[range]: server never became healthy")

        attack = subprocess.Popen(
            [tool, "-R", "-u", f"http://127.0.0.1:{port}/", "-c", "4", "-r", "4",
             "-a", "5", "-b", "2000", "-l", "10"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _, err = attack.communicate(timeout=60)
        attack = None

        m = re.search(rb"range set: (\d+) specs, (\d+) byte request", err)
        if not m:
            raise SystemExit("FAIL[range]: tool did not report its range set")
        specs, req_bytes = int(m.group(1)), int(m.group(2))
        if specs != 2002:
            raise SystemExit(f"FAIL[range]: expected 2002 specs, got {specs}")

        time.sleep(1.5)  # let the reporter emit a fresh line
        committed_mb = server.range_committed_mb()
        if committed_mb <= 0:
            raise SystemExit("FAIL[range]: server committed nothing; "
                             "the Range header did not land")
        # Per request: one small header vs specs x body.
        factor = (committed_mb * 1e6) / req_bytes
        if factor < 1000:
            raise SystemExit(f"FAIL[range]: amplification only {factor:.0f}x")
        print(f"  amplification: OK ({specs} specs, {req_bytes}B request -> "
              f"{committed_mb:.0f}MB committed, {factor:.0f}x)")
    finally:
        terminate(attack)
        if server:
            server.stop()


def main():
    sweep_stale_servers()
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    tool, mock = sys.argv[1], sys.argv[2]
    big = ("--body-bytes", "2000000")

    print("e2e: slow headers (Slowloris)")
    # Workers pinned reading a request that never ends -> no progress at all.
    run_case("vulnerable is wedged", tool, mock, free_port(), "-H", (), (),
             expect_progress=False, saturation_field=0)
    # A header timeout reaps the slow senders, so the server keeps making progress.
    run_case("header timeout defends", tool, mock, free_port(), "-H",
             ("--header-timeout", "2"), (), expect_progress=True)

    print("e2e: slow body (R-U-Dead-Yet)")
    # Workers pinned waiting for a request body that never arrives.
    slow_body_args = ("-i", "5", "-s", "100000")
    run_case("vulnerable is wedged", tool, mock, free_port(), "-B", (),
             slow_body_args, expect_progress=False, saturation_field=0)
    # Same asymmetry as slow read, for the same reason: the headers completed
    # instantly, so a header timeout has nothing to fire on.
    run_case("header timeout does NOT defend", tool, mock, free_port(), "-B",
             ("--header-timeout", "2"), slow_body_args, expect_progress=False,
             saturation_field=0)
    # The matching defense is a request-body timeout.
    run_case("body timeout defends", tool, mock, free_port(), "-B",
             ("--body-timeout", "2"), slow_body_args, expect_progress=True)

    print("e2e: slow read")
    slow_read_args = ("-w", "1", "-y", "8", "-z", "5", "-n", "3")
    # Workers pinned *sending* a response the client refuses to accept. Index 3 is
    # stuck_sending: it proves the mechanism is flow control, not a stalled request.
    run_case("vulnerable is wedged", tool, mock, free_port(), "-X", big,
             slow_read_args, expect_progress=False, saturation_field=3)
    # The key asymmetry: the Slowloris defense does nothing here, because the
    # slow-read request is complete and arrives instantly.
    run_case("header timeout does NOT defend", tool, mock, free_port(), "-X",
             big + ("--header-timeout", "2"), slow_read_args,
             expect_progress=False, saturation_field=3)
    # The matching defense is a send timeout.
    run_case("send timeout defends", tool, mock, free_port(), "-X",
             big + ("--send-timeout", "2"), slow_read_args, expect_progress=True)

    print("e2e: range (Apache killer)")
    run_range_case(tool, mock, free_port())

    print("e2e: all checks passed")


if __name__ == "__main__":
    main()
