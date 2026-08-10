// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Covers URL parsing and flag parsing, including backward compatibility with the
// classic slowhttptest flag set (notably "-v level", which takes an argument).
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "slowhttp/cli.hpp"
#include "slowhttp/config.hpp"

using slowhttp::CliResult;
using slowhttp::Config;
using slowhttp::Mode;
using slowhttp::Target;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

// Runs parse_cli over a literal argv.
static CliResult run(std::vector<const char*> args, Config& cfg) {
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (const char* a : args) argv.push_back(const_cast<char*>(a));
  return slowhttp::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
}

static void test_url_parsing() {
  Target t;
  std::string err;

  check(slowhttp::parse_url("http://example.com/", t, err), "plain http URL");
  check(t.host == "example.com" && t.port == "80" && t.path == "/",
        "http defaults to port 80");

  check(slowhttp::parse_url("https://example.com/a/b?c=d", t, err), "https URL");
  check(t.port == "443" && t.path == "/a/b?c=d", "https defaults to 443, keeps query");
  check(t.tls(), "https target reports tls()");

  check(slowhttp::parse_url("http://host:8080/x", t, err), "explicit port");
  check(t.host == "host" && t.port == "8080", "explicit port parsed");

  check(slowhttp::parse_url("http://host", t, err), "no trailing slash");
  check(t.path == "/", "missing path defaults to /");

  check(!slowhttp::parse_url("example.com/", t, err), "scheme is required");
  check(!slowhttp::parse_url("ftp://example.com/", t, err), "scheme must be http(s)");
  check(!slowhttp::parse_url("http://", t, err), "host is required");
}

static void test_flags() {
  {  // Classic "-v level" form must keep working; a bare -v must not eat the URL.
    Config cfg;
    check(run({"slowhttptest-ng", "-v", "2", "-u", "http://h/"}, cfg) == CliResult::kRun,
          "-v takes a level argument (classic parity)");
    check(cfg.log_level == 2, "-v 2 sets log level 2");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-v", "9"}, cfg) == CliResult::kError,
          "-v rejects out-of-range level");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-c", "100", "-r", "20", "-l", "30", "-i", "5"},
              cfg) == CliResult::kRun, "numeric flags parse");
    check(cfg.connections == 100 && cfg.rate == 20, "-c and -r applied");
    check(cfg.duration.count() == 30 && cfg.interval.count() == 5,
          "-l and -i applied as seconds");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-c", "abc"}, cfg) == CliResult::kError,
          "non-numeric value rejected");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-c", "0"}, cfg) == CliResult::kError,
          "zero connections rejected");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-B"}, cfg) == CliResult::kRun, "-B selects mode");
    check(cfg.mode == Mode::SlowBody, "-B is slow body");
    check(cfg.effective_verb() == "POST", "slow body defaults to POST");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-H"}, cfg) == CliResult::kRun, "-H selects mode");
    check(cfg.effective_verb() == "GET", "slow headers defaults to GET");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-t", "HEAD"}, cfg) == CliResult::kRun, "-t parses");
    check(cfg.effective_verb() == "HEAD", "-t overrides the default verb");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-u", "not-a-url"}, cfg) == CliResult::kError,
          "bad URL rejected");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "stray"}, cfg) == CliResult::kError,
          "stray positional argument rejected");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-c"}, cfg) == CliResult::kError,
          "missing required argument rejected");
  }
  {  // Default target matches the classic tool.
    Config cfg;
    check(run({"slowhttptest-ng"}, cfg) == CliResult::kRun, "no args is valid");
    check(cfg.target.host == "localhost" && cfg.target.port == "80",
          "defaults to http://localhost/");
  }
}

int main() {
  test_url_parsing();
  test_flags();
  if (failures == 0) {
    std::printf("cli: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "cli: %d check(s) failed\n", failures);
  return 1;
}
