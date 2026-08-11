#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for TLS, proxying, the availability probe and the reports.

`e2e_attacks.py` proves the four attacks still do damage. This one proves the
machinery around them is honest:

  * an https target is really attacked over TLS, and through a CONNECT tunnel
  * a plain-http request through a proxy reaches the origin in absolute-URI form
  * the probe measures availability, including through its own separate proxy
  * a proxy that refuses to tunnel is reported as a failure, never as a pass
  * the capacity staircase brackets the denial threshold around the worker count
  * a target that is already unhealthy yields "inconclusive", not a finding
  * the HTML and JSON reports agree and the HTML fetches nothing at view time

The last two are the ones worth having. A tool that reports a confident verdict
when it could not measure anything is worse than one that reports nothing.

Usage: e2e_transport.py <slowhttptest-ng> <mock_slow_server.py> <mock_proxy.py>
"""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

WORKERS = 4
failures = []


def fail(name, why):
    print(f"  {name}: FAIL - {why}")
    failures.append(name)


def ok(name, detail=""):
    print(f"  {name}: OK{(' (' + detail + ')') if detail else ''}")


def terminate(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def wait_until(predicate, timeout, interval=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def port_open(port, tls=False, timeout=2.0):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname="localhost")
            s.settimeout(timeout)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            return bool(s.recv(128))
    except (OSError, ssl.SSLError, socket.timeout):
        return False


def start_server(mock, port, extra=(), workers=WORKERS):
    log = tempfile.NamedTemporaryFile(mode="w+", suffix=".log", delete=False)
    proc = subprocess.Popen(
        [sys.executable, mock, str(port), "--workers", str(workers), *extra],
        stdout=log, stderr=subprocess.DEVNULL)
    return proc, log


def server_served(log_path):
    with open(log_path) as fh:
        m = re.findall(r"served: (\d+)", fh.read())
    return int(m[-1]) if m else 0


def run_tool(tool, args, timeout=180):
    """Runs the tool to completion; returns (exit code, stderr text)."""
    proc = subprocess.Popen([tool, *args], stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    try:
        _, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
        return None, err.decode("utf-8", "replace")
    return proc.returncode, err.decode("utf-8", "replace")


def make_cert(tmpdir):
    """Self-signed cert for the mock https server, or None if openssl is absent."""
    if not shutil.which("openssl"):
        return None, None
    cert = os.path.join(tmpdir, "cert.pem")
    key = os.path.join(tmpdir, "key.pem")
    rc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    return (cert, key) if rc == 0 else (None, None)


def tls_supported(tool):
    _, err = run_tool(tool, ["-u", "https://127.0.0.1:1/", "-c", "1", "-l", "1",
                             "--no-probe"], timeout=30)
    return "no TLS backend" not in err


# --------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------

def case_https(tool, mock, cert, key, port):
    """The attack must actually run over TLS and deny service."""
    server, log = start_server(mock, port, ("--tls-cert", cert, "--tls-key", key))
    try:
        if not wait_until(lambda: port_open(port, tls=True), timeout=15):
            return fail("https attack", "server never became healthy")
        code, err = run_tool(tool, [
            "-u", f"https://127.0.0.1:{port}/", "-c", str(WORKERS * 2),
            "-r", "50", "-i", "5", "-l", "12", "-p", "2",
            "--probe-interval", "1"])
        if "TLS: TLS" not in err:
            return fail("https attack", "tool never reported a TLS session")
        if "SERVICE DENIED" not in err:
            return fail("https attack", "expected the vulnerable server to be denied")
        if code != 0:
            return fail("https attack", f"unexpected exit code {code}")
        m = re.search(r"TLS: (\S+)", err)
        ok("https attack", m.group(1) if m else "")
    finally:
        terminate(server)


def case_https_via_proxy(tool, mock, proxy_script, cert, key, port, pport):
    """https through CONNECT: the tunnel must stay byte-exact or TLS breaks."""
    server, log = start_server(mock, port, ("--tls-cert", cert, "--tls-key", key))
    proxy = subprocess.Popen([sys.executable, proxy_script, str(pport)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_until(lambda: port_open(port, tls=True), timeout=15):
            return fail("https via CONNECT", "server never became healthy")
        time.sleep(1)
        code, err = run_tool(tool, [
            "-u", f"https://127.0.0.1:{port}/", "-d", f"127.0.0.1:{pport}",
            "-c", str(WORKERS * 2), "-r", "50", "-i", "5", "-l", "12",
            "-p", "3", "--probe-interval", "1"])
        if "TLS: TLS" not in err:
            return fail("https via CONNECT", "TLS never completed inside the tunnel")
        if "SERVICE DENIED" not in err:
            return fail("https via CONNECT", "expected service to be denied")
        ok("https via CONNECT")
    finally:
        terminate(proxy)
        terminate(server)


def case_http_via_proxy(tool, mock, proxy_script, port, pport):
    """Plain http through a proxy: absolute-URI form must reach the origin."""
    server, log = start_server(mock, port)
    proxy = subprocess.Popen([sys.executable, proxy_script, str(pport)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_until(lambda: port_open(port), timeout=15):
            return fail("http via proxy", "server never became healthy")
        time.sleep(1)
        before = server_served(log.name)
        code, err = run_tool(tool, [
            "-u", f"http://127.0.0.1:{port}/", "-d", f"127.0.0.1:{pport}",
            "-c", "6", "-r", "50", "-i", "5", "-l", "10", "-p", "2",
            "--probe-interval", "1"])
        if code != 0:
            return fail("http via proxy", f"exit code {code}: {err[-300:]}")
        time.sleep(1.5)
        # The probes are ordinary requests; if absolute-URI rewriting were broken
        # the proxy could not forward them and the origin would serve nothing.
        delta = server_served(log.name) - before
        if delta <= 0:
            return fail("http via proxy",
                        "origin served nothing, so nothing was forwarded")
        ok("http via proxy", f"origin served {delta} forwarded requests")
    finally:
        terminate(proxy)
        terminate(server)


def case_probe_proxy(tool, mock, proxy_script, port, pport):
    """-e sends only the probe through the proxy; the attack still goes direct."""
    server, log = start_server(mock, port)
    proxy = subprocess.Popen([sys.executable, proxy_script, str(pport)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_until(lambda: port_open(port), timeout=15):
            return fail("probe-only proxy", "server never became healthy")
        time.sleep(1)
        code, err = run_tool(tool, [
            "-u", f"http://127.0.0.1:{port}/", "-e", f"127.0.0.1:{pport}",
            "-c", str(WORKERS * 3), "-r", "50", "-i", "5", "-l", "12",
            "-p", "2", "--probe-interval", "1"])
        if "SERVICE DENIED" not in err:
            return fail("probe-only proxy",
                        "probe through the proxy should still have seen denial")
        ok("probe-only proxy")
    finally:
        terminate(proxy)
        terminate(server)


def case_proxy_refuses(tool, mock, proxy_script, cert, key, port, pport):
    """A proxy that will not tunnel must be a loud failure, never a silent pass."""
    server, log = start_server(mock, port, ("--tls-cert", cert, "--tls-key", key))
    proxy = subprocess.Popen([sys.executable, proxy_script, str(pport), "--deny"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        code, err = run_tool(tool, [
            "-u", f"https://127.0.0.1:{port}/", "-d", f"127.0.0.1:{pport}",
            "-c", "4", "-r", "50", "-l", "20", "-p", "2"])
        if code == 0:
            return fail("proxy refuses CONNECT",
                        "exited 0 despite never establishing a connection")
        if "refused CONNECT" not in err:
            return fail("proxy refuses CONNECT",
                        f"no explanation of why setup failed: {err[-300:]}")
        ok("proxy refuses CONNECT", f"exit {code} with the proxy's own reason")
    finally:
        terminate(proxy)
        terminate(server)


def case_capacity(tool, mock, port):
    """The staircase must bracket the threshold around the server's worker count."""
    server, log = start_server(mock, port, workers=8)
    try:
        if not wait_until(lambda: port_open(port), timeout=15):
            return fail("capacity bracket", "server never became healthy")
        code, err = run_tool(tool, [
            "-u", f"http://127.0.0.1:{port}/", "-c", "32", "-r", "50", "-i", "5",
            "-p", "2", "--probe-interval", "1", "--capacity",
            "--capacity-start", "4", "--capacity-step", "4",
            "--capacity-max", "16", "--capacity-hold", "5"])
        m = re.search(r"denial threshold: (\d+) < n <= (\d+)", err)
        if not m:
            return fail("capacity bracket", f"no bracket reported: {err[-400:]}")
        lo, hi = int(m.group(1)), int(m.group(2))
        # 8 workers: the level that pins all of them is where service stops.
        if not (lo < 8 <= hi):
            return fail("capacity bracket",
                        f"bracket {lo} < n <= {hi} does not contain the 8 workers")
        ok("capacity bracket", f"{lo} < n <= {hi}")
    finally:
        terminate(server)


def case_inconclusive(tool, mock, port):
    """An already-unhealthy target must not be reported as a finding.

    The server is started with no workers at all, so connections sit in the
    listen backlog and nothing is ever answered -- including the baseline probes.
    The tool must decline to conclude rather than claim it caused the outage.
    """
    server, log = start_server(mock, port, workers=0)
    try:
        time.sleep(1.5)
        code, err = run_tool(tool, [
            "-u", f"http://127.0.0.1:{port}/", "-c", "4", "-r", "50", "-l", "10",
            "-p", "1", "--probe-interval", "1"])
        if "INCONCLUSIVE" not in err:
            return fail("unhealthy baseline",
                        f"expected INCONCLUSIVE, got: {err[-400:]}")
        if "SERVICE DENIED" in err:
            return fail("unhealthy baseline",
                        "claimed a denial it could not have caused")
        ok("unhealthy baseline", "declined to conclude")
    finally:
        terminate(server)


def case_reports(tool, mock, port, tmpdir):
    """HTML and JSON come from one event log, so they must never disagree."""
    base = os.path.join(tmpdir, "report")
    server, log = start_server(mock, port)
    try:
        if not wait_until(lambda: port_open(port), timeout=15):
            return fail("report artifacts", "server never became healthy")
        code, err = run_tool(tool, [
            "-u", f"http://127.0.0.1:{port}/", "-c", str(WORKERS * 3), "-r", "50",
            "-i", "5", "-l", "12", "-p", "2", "--probe-interval", "1",
            "-g", "-o", base])
        html_path, json_path = base + ".html", base + ".json"
        if not (os.path.exists(html_path) and os.path.exists(json_path)):
            return fail("report artifacts", "one or both files were not written")

        with open(json_path) as fh:
            data = json.load(fh)          # must be valid JSON, not almost-JSON
        with open(html_path) as fh:
            html = fh.read()

        outcome = data["result"]["outcome"]
        if outcome not in ("denied", "degraded", "held", "inconclusive"):
            return fail("report artifacts", f"unknown outcome {outcome!r}")
        if f'"outcome": "{outcome}"' not in html:
            return fail("report artifacts", "HTML and JSON disagree on the outcome")
        if "VULNERABLE" in html:
            return fail("report artifacts",
                        "report frames the result as a property, not an outcome")
        for needed in ("not_ruled_out", "criterion", "denial_threshold"):
            if needed not in data:
                return fail("report artifacts", f"JSON is missing {needed}")
        if not data["not_ruled_out"]:
            return fail("report artifacts", "JSON lists no caveats")
        # Self-contained: nothing may be fetched when the file is opened.
        for bad in ("<script src", "<link ", "cdn.", "googleapis", "gstatic"):
            if bad in html:
                return fail("report artifacts", f"HTML references {bad!r}")
        ok("report artifacts", f"outcome={outcome}, {len(data['not_ruled_out'])} caveats")
    finally:
        terminate(server)


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    tool, mock, proxy_script = sys.argv[1], sys.argv[2], sys.argv[3]
    tmpdir = tempfile.mkdtemp(prefix="slowhttp-e2e-")

    print("e2e: proxying")
    case_http_via_proxy(tool, mock, proxy_script, 8301, 8401)
    case_probe_proxy(tool, mock, proxy_script, 8302, 8402)

    print("e2e: availability probe and verdict")
    case_inconclusive(tool, mock, 8303)
    case_capacity(tool, mock, 8304)

    print("e2e: reporting")
    case_reports(tool, mock, 8305, tmpdir)

    print("e2e: TLS")
    if not tls_supported(tool):
        print("  skipped: this build has no TLS backend")
    else:
        cert, key = make_cert(tmpdir)
        if not cert:
            print("  skipped: openssl not available to make a test certificate")
        else:
            case_https(tool, mock, cert, key, 8306)
            case_https_via_proxy(tool, mock, proxy_script, cert, key, 8307, 8403)
            case_proxy_refuses(tool, mock, proxy_script, cert, key, 8308, 8404)

    shutil.rmtree(tmpdir, ignore_errors=True)
    if failures:
        raise SystemExit(f"e2e: {len(failures)} case(s) failed: {', '.join(failures)}")
    print("e2e: all transport and reporting checks passed")


if __name__ == "__main__":
    main()
