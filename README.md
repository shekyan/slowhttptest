## Disclaimer ##

Any actions and or activities related to the code provided is solely your responsibility.The misuse of the information in this website can result in criminal charges brought against the persons in question. The authors will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this tool to break the law.

# SlowHTTPTest #

[![classic](https://github.com/shekyan/slowhttptest/actions/workflows/classic.yml/badge.svg)](https://github.com/shekyan/slowhttptest/actions/workflows/classic.yml)
[![ng](https://github.com/shekyan/slowhttptest/actions/workflows/ng.yml/badge.svg)](https://github.com/shekyan/slowhttptest/actions/workflows/ng.yml)
[![CodeQL](https://github.com/shekyan/slowhttptest/actions/workflows/codeql.yml/badge.svg)](https://github.com/shekyan/slowhttptest/actions/workflows/codeql.yml)

SlowHTTPTest is a highly configurable tool that simulates some Application Layer Denial of Service attacks by prolonging HTTP connections in different ways.

Use it to test your web server for DoS vulnerabilities, or just to figure out how many concurrent connections it can handle.

**Run it only against systems you own or have explicit written permission to
test.** It is built for defensive work — availability testing, capacity
planning, and checking that HTTP-layer DoS mitigations do what you think they
do. Pointed at infrastructure that is not yours, it is an attack, and in most
jurisdictions a crime.

SlowHTTPTest works on majority of Linux platforms, OS X and Cygwin - a Unix-like environment and command-line interface for Microsoft Windows, and comes with a Dockerfile to make things even easier.

Check out [Wiki](https://github.com/shekyan/slowhttptest/wiki) for installation and usage details.

Latest official image is available at [Docker Hub](https://hub.docker.com/repository/docker/shekyan/slowhttptest):
`docker pull shekyan/slowhttptest:latest`

## Trying `slowhttptest-ng` (beta) ##

There is a rewrite of this tool in modern C++, and it would benefit from being
run against things its author does not own.

It installs **alongside** the existing binary. Nothing is renamed: `slowhttptest`
still means the tool described above, and stays installed and unchanged.

### What differs

| | `slowhttptest` | `slowhttptest-ng` |
|---|---|---|
| slow headers (`-H`), slow body (`-B`), range (`-R`), slow read (`-X`) | yes | yes |
| HTTP/2 slow read, rapid reset, CONTINUATION flood | no | yes |
| chunked request body (`--chunked`) | no | yes |
| flow-control throttling (`--window-trickle`) | no | yes |
| capacity search (`--capacity`) | no | yes |
| address family pinning (`-4` / `-6`) | no | yes |
| repeatable custom headers | one (`-1`) | repeatable, and sent on the probe |
| machine-readable report | CSV | JSON |
| availability verdict | `YES` / `NO` | served / slow / denied, with a verdict and caveats |
| exit codes | `-1` on error | `2` / `3` / `4`, with the criterion in the JSON |

**The HTML reports differ in a way worth knowing before you archive one.** The
classic report pulls Google Charts from `https://www.google.com/jsapi` when the
page is opened, so it needs internet access *at view time* and renders as a bare
table without it — which is what happens in an air-gapped network, a locked-down
browser, or a year from now if that endpoint moves. The `ng` report is
self-contained: the chart is inline SVG and the file has no external resource
loads, so it renders the same offline and keeps rendering after the fact.

`docker run --rm --entrypoint slowhttptest-ng shekyan/slowhttptest:ng -u https://target/ -c 1000 -H`

What it adds:

* **HTTP/2 attacks** — slow read (CVE-2019-9517), rapid reset (CVE-2023-44487)
  and the CONTINUATION flood.
* **A verdict instead of a socket census.** The report says whether service was
  actually denied, and lists what could explain the result other than the attack.
* **An exit code that distinguishes "nothing was tested" from "the target held"**,
  so an unreachable host stops passing as a clean run in CI.

Three things deliberately differ from the classic tool: CSV output is replaced by
JSON, exit codes are `2`/`3` rather than `-1`, and the report is organised around
availability rather than socket states. All flags otherwise mean what they always
have.

See the [latest release notes](https://github.com/shekyan/slowhttptest/releases/latest),
and please open an issue if it gets something wrong — a report that misdescribes a
run is the worst bug this tool can have, and that is exactly what a beta is for.
