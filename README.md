## Disclaimer ##

Any actions and or activities related to the code provided is solely your responsibility.The misuse of the information in this website can result in criminal charges brought against the persons in question. The authors will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this tool to break the law.

# SlowHTTPTest #

[![ng](https://github.com/shekyan/slowhttptest/actions/workflows/ng.yml/badge.svg)](https://github.com/shekyan/slowhttptest/actions/workflows/ng.yml)
[![CodeQL](https://github.com/shekyan/slowhttptest/actions/workflows/codeql.yml/badge.svg)](https://github.com/shekyan/slowhttptest/actions/workflows/codeql.yml)

SlowHTTPTest is a highly configurable tool that simulates some Application Layer Denial of Service attacks by prolonging HTTP connections in different ways.

Use it to test your web server for DoS vulnerabilites, or just to figure out how many concurrent connections it can handle.
SlowHTTPTest works on majority of Linux platforms, OS X and Cygwin - a Unix-like environment and command-line interface for Microsoft Windows, and comes with a Dockerfile to make things even easier.

Check out [Wiki](https://github.com/shekyan/slowhttptest/wiki) for installation and usage details.

Latest official image is available at [Docker Hub](https://hub.docker.com/repository/docker/shekyan/slowhttptest):
`docker pull shekyan/slowhttptest:latest`

## Trying `slowhttptest-ng` (beta) ##

There is a rewrite of this tool in modern C++, and it would benefit from being
run against things its author does not own.

It installs **alongside** the existing binary. Nothing is renamed: `slowhttptest`
still means the tool described above, and stays installed and unchanged.

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

See the [v2.0.0-beta1 release notes](https://github.com/shekyan/slowhttptest/releases/tag/v2.0.0-beta1),
and please open an issue if it gets something wrong — a report that misdescribes a
run is the worst bug this tool can have, and that is exactly what a beta is for.
