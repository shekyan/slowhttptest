"""Regenerates print_usage() in src/config/cli.cpp with computed alignment.

Run after adding or changing an option:

    python3 tools/gen_usage.py

Edit SECTIONS below, never the generated C++.

Hand-alignment is what this replaced. Short flags were padded to one column
while long ones ran straight into their own descriptions, and the sections that
had been pushed past the bottom of a terminal read to users as missing
features -- which is how the slow-read options came to be reported absent when
they had been there all along.
"""
import os
import textwrap

DESC_COL = 26      # description starts here
WIDTH = 79         # wrap the whole line here

SECTIONS = [
    ("Test modes", [
        ("-H", "slow headers a.k.a. Slowloris (default)"),
        ("-B", "slow body a.k.a. R-U-Dead-Yet"),
        ("-R", "range attack a.k.a. Apache killer"),
        ("-X", "slow read"),
    ]),
    ("Target", [
        ("-u URL", "absolute URL of target (http://localhost/)"),
        ("-d host:port", "route all traffic through this HTTP proxy"),
        ("-e host:port", "route only the availability probe through a proxy"),
        ("-4, --ipv4", "use IPv4 only; pins the run to one network path"),
        ("-6, --ipv6", "use IPv6 only; pins the run to one network path"),
    ]),
    ("Load", [
        ("-c num", "target number of concurrent connections (50)"),
        ("-r rate", "new connections per second (50)"),
        ("-l seconds", "test length (240)"),
        ("-i seconds", "interval between followup data (10)"),
        ("--connect-timeout SEC", "drop a stalled connection, reuse the slot (10)"),
        ("--max-connecting N", "cap connections mid-handshake (5000; 0 = no cap)"),
    ]),
    ("Request", [
        ("-t verb", "request verb (GET, or POST for -B)"),
        ("-f type", "Content-Type header value"),
        ("-m accept", "Accept header value"),
        ("-j cookie", "Cookie header value"),
        ("-1, --header H", "extra header, repeatable; also sent on the probe"),
        ("-A, --user-agent UA", "User-Agent; identifies the tool by default"),
        ("-x bytes", "max length of each random name/value pair (32)"),
        ("--random-user-agent", "present as Chrome, Firefox or Safari instead"),
        ("--no-referer", "do not send the Referer marker"),
    ]),
    ("Slow body (-B) options", [
        ("-s bytes", "Content-Length header value (4096)"),
        ("-P, --data D", "request body; @file reads it from a file"),
    ]),
    ("Range (-R) options", [
        ("-a start", "left boundary of the ranges in the Range header (5)"),
        ("-b bytes", "ceiling for the Range header right boundary (2000)"),
    ]),
    ("Slow read (-X) options", [
        ("-n seconds", "interval between read() calls (1)"),
        ("-z bytes", "bytes to read per read() call (5)"),
        ("-w bytes", "advertised window range, low end (1)"),
        ("-y bytes", "advertised window range, high end (512)"),
        ("-k num", "repeat the request N times per connection (1)"),
    ]),
    ("Availability probe (the verdict is based on this)", [
        ("-p seconds", "probe timeout; no response = unavailable (5)"),
        ("--probe-interval SEC", "seconds between probes (2)"),
        ("--no-probe", "do not measure availability; no verdict or report"),
    ]),
    ("Capacity search (brackets the denial threshold instead of guessing)", [
        ("--capacity", "hold at each level, probe, then step up"),
        ("--capacity-start N", "first level (32)"),
        ("--capacity-step N", "increment between levels (32)"),
        ("--capacity-max N", "ceiling (defaults to -c)"),
        ("--capacity-hold SEC", "seconds held at each level (15)"),
    ]),
    ("Reporting", [
        ("-g", "write a report (self-contained HTML + JSON)"),
        ("-o base", "report base name; writes base.html and base.json"),
        ("--availability-threshold F", "share of probes served for the CI pass (0.95)"),
        ("--fail-on-status LIST", "codes that also fail the CI gate, e.g. 5xx"),
    ]),
    ("Output", [
        ("-v level", "verbosity 0-4 (1); 4 details connect failures"),
        ("-q, --quiet", "no console output at all"),
        ("-h, --help", "this help"),
        ("-V, --version", "version, TLS support and connection ceiling"),
    ]),
]

FOOTER = [
    "",
    "Client certificates come from SSL_CERT and SSL_KEY, as in the classic tool.",
    "See slowhttptest-ng(1) for the detail behind any of these.",
    "Run only against systems you are authorized to test.",
]


def render():
    out = []
    for title, opts in SECTIONS:
        out.append("")
        out.append(title + ":")
        for flag, desc in opts:
            left = "  " + flag
            body = textwrap.wrap(desc, WIDTH - DESC_COL)
            if len(left) <= DESC_COL - 2:
                out.append(left.ljust(DESC_COL) + body[0])
                rest = body[1:]
            else:
                # Too long to share a line; description starts underneath.
                out.append(left)
                rest = body
            for line in rest:
                out.append(" " * DESC_COL + line)
    out.extend(FOOTER)
    return out


def as_cpp(lines):
    esc = []
    for line in lines:
        line = line.replace("\\", "\\\\").replace('"', '\\"')
        esc.append('      "%s\\n"' % line)
    return "\n".join(esc)


body = as_cpp(render())

func = ('void print_usage() {\n'
        '  // Layout is generated, not hand-aligned: descriptions start at a fixed\n'
        '  // column and options too long to share the line get it to themselves.\n'
        '  // Hand-alignment is what broke here, since a long option such as\n'
        '  // --availability-threshold ran straight into its own description.\n'
        '  //\n'
        '  // Grouped by what the operator is trying to do rather than by flag\n'
        '  // length: target, load, request shape, per-mode tuning, measurement,\n'
        '  // reporting, output.\n'
        '  std::printf(\n'
        '      "slowhttptest-ng %s - modern C++ rewrite of slowhttptest\\n"\n'
        '      "Usage: slowhttptest-ng [options]\\n",\n'
        '      kToolVersion);\n'
        '  std::printf(\n' + body + ');\n}\n\n')

p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 os.pardir, "src", "config", "cli.cpp")
s = open(p).read()
start = s.index("void print_usage() {")
end = s.index("bool parse_url(")
open(p, "w").write(s[:start] + func + s[end:])
print("print_usage regenerated")
