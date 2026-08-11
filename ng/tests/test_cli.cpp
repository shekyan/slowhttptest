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

  // IPv6 literals: the address is full of colons, so the port separator cannot
  // be found by splitting on the first one.
  check(slowhttp::parse_url("http://[::1]:8080/x", t, err), "bracketed IPv6 URL");
  check(t.host == "::1" && t.port == "8080" && t.path == "/x",
        "IPv6 host and port split at the bracket, not the first colon");
  check(t.host_in_url() == "[::1]" && t.authority() == "[::1]:8080",
        "IPv6 literal goes back inside brackets for HTTP syntax");

  check(slowhttp::parse_url("https://[2001:db8::42]/", t, err), "IPv6 without port");
  check(t.host == "2001:db8::42" && t.port == "443",
        "IPv6 without a port takes the scheme default");

  check(!slowhttp::parse_url("http://[::1:8080/", t, err),
        "unterminated IPv6 bracket rejected");

  check(slowhttp::parse_url("http://example.com/", t, err), "plain host after IPv6");
  check(!t.ipv6_literal() && t.host_in_url() == "example.com",
        "a normal host is never bracketed");

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

static void test_proxy_flags() {
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-d", "10.0.0.1:3128"}, cfg) == CliResult::kRun,
          "-d parses host:port");
    check(cfg.proxy.host == "10.0.0.1" && cfg.proxy.port == "3128",
          "-d endpoint applied");
    check(cfg.proxy.enabled() && !cfg.probe_proxy.enabled(),
          "-d configures the traffic proxy only");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-e", "127.0.0.1:8888"}, cfg) == CliResult::kRun,
          "-e parses host:port");
    check(cfg.probe_proxy.enabled() && !cfg.proxy.enabled(),
          "-e configures the probe proxy only");
  }
  {  // An implied port would be a guess, and a wrong guess sends the whole test
     // somewhere silent.
    Config cfg;
    check(run({"slowhttptest-ng", "-d", "proxy.local"}, cfg) == CliResult::kError,
          "-d requires an explicit port");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-d", "proxy.local:http"}, cfg) == CliResult::kError,
          "-d rejects a non-numeric port");
  }
  {  // Through a proxy, a plain-http request must name the absolute URI; through
     // a CONNECT tunnel it must not.
    Config cfg;
    run({"slowhttptest-ng", "-u", "http://example.test:8080/a", "-d",
         "127.0.0.1:3128"}, cfg);
    check(cfg.request_target() == "http://example.test:8080/a",
          "plain http through a proxy uses absolute-URI form");
    check(cfg.connect_host() == "127.0.0.1" && cfg.connect_port() == "3128",
          "connections go to the proxy, not the origin");
  }
  {
    Config cfg;
    run({"slowhttptest-ng", "-u", "https://example.test/a", "-d",
         "127.0.0.1:3128"}, cfg);
    check(cfg.request_target() == "/a",
          "https through a CONNECT tunnel keeps origin-form");
  }
  {
    Config cfg;
    run({"slowhttptest-ng", "-u", "http://example.test/a"}, cfg);
    check(cfg.request_target() == "/a", "no proxy means origin-form");
    check(cfg.connect_host() == "example.test", "no proxy means dial the origin");
  }
}

static void test_probe_and_report_flags() {
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-p", "9"}, cfg) == CliResult::kRun, "-p parses");
    check(cfg.probe_timeout.count() == 9, "-p sets the probe timeout in seconds");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--probe-interval", "0.5"}, cfg) == CliResult::kRun,
          "--probe-interval accepts sub-second values");
    check(cfg.probe_interval.count() == 500, "--probe-interval applied as ms");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--probe-interval", "0"}, cfg) == CliResult::kError,
          "--probe-interval rejects zero");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-g", "-o", "out/run"}, cfg) == CliResult::kRun,
          "-g and -o parse");
    check(cfg.report && cfg.report_base == "out/run", "report base applied");
  }
  {  // Refusing beats emitting an empty report: the report IS the probe data.
    Config cfg;
    check(run({"slowhttptest-ng", "-g", "--no-probe"}, cfg) == CliResult::kError,
          "-g with --no-probe is refused rather than producing an empty report");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--capacity", "--no-probe"}, cfg) == CliResult::kError,
          "--capacity with --no-probe is refused");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--availability-threshold", "0.8"}, cfg) ==
              CliResult::kRun, "--availability-threshold parses");
    check(cfg.availability_threshold == 0.8, "threshold applied");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--availability-threshold", "1.5"}, cfg) ==
              CliResult::kError, "--availability-threshold rejects > 1");
  }
}

static void test_custom_headers() {
  {  // One -1 was never enough: auth *and* routing is the normal case.
    Config cfg;
    check(run({"slowhttptest-ng", "-1", "Authorization: Bearer abc",
               "-1", "X-Tenant: acme"}, cfg) == CliResult::kRun,
          "-1 is repeatable");
    check(cfg.extra_headers.size() == 2, "both headers kept, not overwritten");
    check(cfg.extra_headers[0] == "Authorization: Bearer abc" &&
              cfg.extra_headers[1] == "X-Tenant: acme",
          "headers kept in the order given");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--header", "X-A: 1"}, cfg) == CliResult::kRun,
          "--header is an alias for -1");
    check(cfg.extra_headers.size() == 1, "--header accumulates too");
  }
  {  // A header is spliced straight into the request; CR/LF would let the value
     // inject further headers, or a whole second request.
    Config cfg;
    check(run({"slowhttptest-ng", "-1", "X-A: 1\r\nX-Injected: 2"}, cfg) ==
              CliResult::kError, "CRLF in a header value is rejected");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-1", "no-colon-here"}, cfg) == CliResult::kError,
          "a header without a colon is rejected");
  }
  {  // The cookie and every custom header must ride on the probe as well, or the
     // probe measures a different endpoint than the one under attack.
    Config cfg;
    run({"slowhttptest-ng", "-j", "sid=42", "-1", "Authorization: Bearer abc"}, cfg);
    const std::string block = cfg.caller_headers();
    check(block == "Cookie: sid=42\r\nAuthorization: Bearer abc\r\n",
          "caller_headers renders cookie and custom headers, CRLF-terminated");
  }
  {
    Config cfg;
    run({"slowhttptest-ng"}, cfg);
    check(cfg.caller_headers().empty(), "no cookie or headers means no block");
  }
}

static void test_body_data() {
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-B", "-P", "a=1&b=2"}, cfg) == CliResult::kRun,
          "-P takes a literal body");
    check(cfg.body_data == "a=1&b=2" && cfg.body_data_source == "literal",
          "literal body stored");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-B", "--data", "x=1"}, cfg) == CliResult::kRun,
          "--data is an alias for -P");
  }
  {  // Only slow body sends a body; anywhere else the payload would be silently
     // dropped while the user believed it had been sent.
    Config cfg;
    check(run({"slowhttptest-ng", "-X", "-P", "a=1"}, cfg) == CliResult::kError,
          "-P outside -B is refused rather than ignored");
  }
  {  // A payload at or past the promised Content-Length would finish the request
     // and end the hold, which is the opposite of the attack.
    Config cfg;
    std::string big = "-P";
    check(run({"slowhttptest-ng", "-B", "-s", "16", "-P",
               "0123456789012345678901234567890123456789"}, cfg) ==
              CliResult::kRun, "an oversized payload is accommodated");
    check(cfg.content_length > static_cast<int>(cfg.body_data.size()),
          "Content-Length is raised above the payload so the body stays unfinished");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-B", "-P", "@/nonexistent/body.bin"}, cfg) ==
              CliResult::kError, "a missing @file is an error, not an empty body");
  }
}

static void test_fail_on_status() {
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--fail-on-status", "5xx"}, cfg) ==
              CliResult::kRun, "--fail-on-status accepts a class");
    check(cfg.fail_on_status.matches(503) && cfg.fail_on_status.matches(500),
          "5xx matches any 5xx");
    check(!cfg.fail_on_status.matches(200) && !cfg.fail_on_status.matches(429),
          "5xx does not match other classes");
    check(!cfg.fail_on_status.matches(-1),
          "no response is not a status match; that is a denial, counted elsewhere");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--fail-on-status", "503,429"}, cfg) ==
              CliResult::kRun, "--fail-on-status accepts a list of exact codes");
    check(cfg.fail_on_status.matches(503) && cfg.fail_on_status.matches(429),
          "both listed codes match");
    check(!cfg.fail_on_status.matches(500), "an unlisted 5xx does not match");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--fail-on-status", "banana"}, cfg) ==
              CliResult::kError, "a nonsense spec is rejected");
  }
  {
    Config cfg;
    run({"slowhttptest-ng"}, cfg);
    check(cfg.fail_on_status.empty() && !cfg.fail_on_status.matches(503),
          "without the flag no status fails the gate");
  }
}

static void test_user_agent() {
  {  // This is a testing tool, and by default it says so on every request, so the
     // traffic is identifiable in the target's own logs.
    Config cfg;
    check(run({"slowhttptest-ng"}, cfg) == CliResult::kRun, "no -A is fine");
    check(cfg.user_agent == slowhttp::kDefaultUserAgent,
          "the default identifies the tool");
    check(cfg.user_agent.find("slowhttptest-ng") != std::string::npos,
          "the default names the tool");
    check(cfg.user_agent.find(slowhttp::kProjectUrl) != std::string::npos,
          "the default carries the repository URL so it can be looked up");
    check(cfg.user_agent.find(slowhttp::kToolVersion) != std::string::npos,
          "the default carries the version");
    check(!cfg.random_user_agent, "randomization is off unless asked for");
    // No run should ever silently impersonate a browser.
    for (int i = 0; i < slowhttp::kUserAgentCount; ++i)
      check(cfg.user_agent != slowhttp::kUserAgents[i],
            "the default is never one of the browser agents");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--random-user-agent"}, cfg) == CliResult::kRun,
          "--random-user-agent parses");
    bool known = false;
    for (int i = 0; i < slowhttp::kUserAgentCount; ++i)
      if (cfg.user_agent == slowhttp::kUserAgents[i]) known = true;
    check(known, "--random-user-agent picks from the browser pool");
    check(cfg.user_agent.find("slowhttptest") == std::string::npos,
          "a browser agent does not announce the tool");
  }
  {  // Both name the agent; honouring one and dropping the other silently would
     // be worse than refusing.
    Config cfg;
    check(run({"slowhttptest-ng", "-A", "x/1", "--random-user-agent"}, cfg) ==
              CliResult::kError,
          "-A and --random-user-agent together are refused");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-A", "my-scanner/1.0"}, cfg) == CliResult::kRun,
          "-A overrides the agent");
    check(cfg.user_agent == "my-scanner/1.0", "-A value applied verbatim");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--user-agent", "x/2"}, cfg) == CliResult::kRun,
          "--user-agent is an alias for -A");
    check(cfg.user_agent == "x/2", "--user-agent value applied");
  }
  {  // The pool should be current browsers, not the 2014-era set the classic
     // tool shipped, which now marks traffic as anomalous on sight.
     bool chrome = false, firefox = false, safari = false;
     for (int i = 0; i < slowhttp::kUserAgentCount; ++i) {
       const std::string ua = slowhttp::kUserAgents[i];
       if (ua.find("Chrome/") != std::string::npos &&
           ua.find("Safari/537.36") != std::string::npos) chrome = true;
       if (ua.find("Firefox/") != std::string::npos) firefox = true;
       if (ua.find("Version/") != std::string::npos &&
           ua.find("Safari/605") != std::string::npos) safari = true;
     }
     check(chrome && firefox && safari,
           "the pool covers Chrome, Firefox and Safari");
     for (int i = 0; i < slowhttp::kUserAgentCount; ++i) {
       const std::string ua = slowhttp::kUserAgents[i];
       check(ua.find("MSIE") == std::string::npos &&
                 ua.find("PhantomJS") == std::string::npos,
             "no long-dead browsers in the pool");
     }
  }
}

static void test_quiet() {
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-q"}, cfg) == CliResult::kRun, "-q parses");
    check(cfg.log_level == 0, "-q is level 0");
    check(!cfg.verbose, "-q is not verbose");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--quiet"}, cfg) == CliResult::kRun,
          "--quiet is an alias for -q");
    check(cfg.log_level == 0, "--quiet is level 0");
  }
  {  // Quiet is about the console, not about the artifacts.
    Config cfg;
    check(run({"slowhttptest-ng", "-q", "-g", "-o", "out"}, cfg) == CliResult::kRun,
          "-q composes with -g: silence does not disable reporting");
    check(cfg.report, "reporting still on under -q");
  }
}

static void test_capacity_flags() {
  {
    Config cfg;
    check(run({"slowhttptest-ng", "-c", "256", "--capacity", "--capacity-start", "16",
               "--capacity-step", "16", "--capacity-hold", "20"}, cfg) ==
              CliResult::kRun, "capacity flags parse");
    check(cfg.capacity.enabled && cfg.capacity.start == 16 &&
              cfg.capacity.step == 16 && cfg.capacity.hold.count() == 20,
          "capacity plan applied");
    check(cfg.capacity.max == 256, "capacity ceiling defaults to -c");
  }
  {
    Config cfg;
    check(run({"slowhttptest-ng", "--capacity", "--capacity-start", "64",
               "--capacity-max", "32"}, cfg) == CliResult::kError,
          "a ceiling below the first level is refused");
  }
  {  // The connection pool is sized once from -c, so the ceiling has to fit it.
    Config cfg;
    check(run({"slowhttptest-ng", "-c", "10", "--capacity", "--capacity-max", "100"},
              cfg) == CliResult::kRun, "a ceiling above -c is accommodated");
    check(cfg.connections == 100, "-c is raised to reach the capacity ceiling");
  }
}

int main() {
  test_url_parsing();
  test_flags();
  test_proxy_flags();
  test_probe_and_report_flags();
  test_custom_headers();
  test_body_data();
  test_fail_on_status();
  test_user_agent();
  test_quiet();
  test_capacity_flags();
  if (failures == 0) {
    std::printf("cli: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "cli: %d check(s) failed\n", failures);
  return 1;
}
