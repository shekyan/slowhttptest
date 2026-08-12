// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_CONFIG_HPP_
#define SLOWHTTP_CONFIG_HPP_

#include <chrono>
#include <string>
#include <vector>

namespace slowhttp {

enum class Mode { SlowHeaders, SlowBody, SlowRead, Range };

const char* mode_name(Mode m);

extern const char* const kToolVersion;
extern const char* const kProjectUrl;

// The default User-Agent, and the only one used unless the operator asks for
// something else.
//
// This is a testing tool, not an attack tool, and it says so on every request.
// Following the long-standing crawler convention (`name/version (+url)`), the
// traffic is trivially identifiable in the target's own logs: whoever is on the
// receiving end can look it up, correlate it with a scheduled test, and tell it
// apart from a real incident. Disguising it would make that impossible, and the
// people running the target are the people this tool exists to help.
extern const char* const kDefaultUserAgent;

// Current desktop browser agents -- Chrome, Firefox, Safari -- used only when
// --random-user-agent is given.
//
// The legitimate reason to reach for these is that CDNs and WAFs route and
// rate-limit on User-Agent, so a self-identifying agent can be shed before it
// reaches the service and the run then measures the bot-mitigation layer instead.
// When the question is specifically "how does this behave for browser traffic",
// this answers it. It is opt-in because that is a narrower question than the one
// the tool is usually asked, and because the honest default should not require
// an argument.
//
// One agent is chosen per run rather than per connection: mixing agents the
// target may treat differently would make the result unattributable. Whichever
// is used is recorded in the report.
extern const char* const kUserAgents[3];
constexpr int kUserAgentCount = 3;

// Parsed target endpoint.
struct Target {
  std::string scheme = "http";
  std::string host;
  std::string port = "80";
  std::string path = "/";

  bool tls() const { return scheme == "https"; }

  // `host` is stored unbracketed (as the resolver wants it), but an IPv6 literal
  // has to go back inside brackets anywhere it appears in HTTP syntax, or the
  // colons in the address are indistinguishable from the port separator.
  bool ipv6_literal() const { return host.find(':') != std::string::npos; }
  std::string host_in_url() const {
    return ipv6_literal() ? "[" + host + "]" : host;
  }

  // "host:port", the form a CONNECT request and an absolute URI want.
  std::string authority() const { return host_in_url() + ":" + port; }

  std::string default_port() const { return tls() ? "443" : "80"; }

  // What belongs in the Host header. The port is included whenever it is not
  // the scheme's default (RFC 9110 §7.2). Omitting it is not cosmetic: name-based
  // virtual hosts and Host-routing reverse proxies will send the request to a
  // different backend than the one being tested, and strict servers answer 400 --
  // either way the run measures something other than the intended target.
  std::string host_header() const {
    return port == default_port() ? host_in_url() : authority();
  }
};

// An HTTP proxy endpoint. Empty host means "not configured".
struct ProxyEndpoint {
  std::string host;
  std::string port;

  bool enabled() const { return !host.empty(); }
};

// Which HTTP status codes should fail the CI criterion.
//
// Deliberately kept separate from the availability outcome. A 503 *is* a served
// response: the server answered, and calling that "denied" would conflate "it
// refused me" with "it never answered me". But plenty of operators do care about
// a 503 flood, so this gives them a gate without corrupting the measurement.
struct StatusMatcher {
  std::vector<int> exact;    // e.g. 503
  std::vector<int> classes;  // e.g. 5 for any 5xx

  bool empty() const { return exact.empty() && classes.empty(); }

  bool matches(int code) const {
    if (code < 0) return false;
    for (int e : exact)
      if (e == code) return true;
    for (int c : classes)
      if (code / 100 == c) return true;
    return false;
  }
};

// Capacity ("staircase") search knobs. The engine holds `start` connections,
// probes, then steps up by `step` until the service stops answering, which
// brackets the denial threshold between the last level that held and the first
// that did not.
struct CapacityPlan {
  bool enabled = false;
  int start = 32;                       // first level
  int step = 32;                        // increment between levels
  int max = 0;                          // ceiling; 0 => Config::connections
  std::chrono::seconds hold{15};        // time held at each level
};

// Full test configuration. Field names mirror the classic CLI flags so the flag
// parser stays a thin mapping and existing muscle memory carries over.
struct Config {
  Target target;
  Mode mode = Mode::SlowHeaders;

  int connections = 50;                  // -c  target concurrent connections
  int rate = 50;                         // -r  new connections per second

  // --connect-timeout: how long a connection may sit unestablished before it is
  // dropped and the slot reused. 0 leaves it to the OS.
  //
  // The OS default is far too long here: macOS retries a SYN for 75 seconds, so
  // against a target that is dropping them, slots fill with connections that
  // will never complete and contribute nothing. Recycling them keeps the SYN
  // pressure up and, incidentally, stops thousands of half-open sockets
  // accumulating -- which is its own problem, since the kernel is slow to reap
  // a process holding them.
  std::chrono::seconds connect_timeout{10};
  std::chrono::seconds duration{240};    // -l  total test length
  std::chrono::seconds interval{10};     // -i  followup dribble interval
  int max_random_data_len = 32;          // -x  max size of each random name/value
  int content_length = 4096;             // -s  Content-Length for body modes

  std::string verb;                      // -t  (defaults per mode)
  // -A, or kDefaultUserAgent, or -- with --random-user-agent -- one of
  // kUserAgents picked for the run.
  std::string user_agent;
  bool random_user_agent = false;        // --random-user-agent
  std::string content_type =             // -f
      "application/x-www-form-urlencoded";
  std::string accept =                   // -m
      "text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5";
  std::string cookie;                    // -j
  // Sent on every request, as the classic tool has always done. Override with
  // -1 "Referer: ..."; clear it with --no-referer.
  std::string referer = "TESTING_PURPOSES_ONLY";
  // -1 / --header, repeatable. One flag was never enough: an authenticated
  // target routinely needs an Authorization header *and* a routing or tenant
  // header, and the classic tool's single slot forced people to choose.
  std::vector<std::string> extra_headers;

  // -P / --data: the request body for -B, literal or read from @file. Without it
  // the body is the classic "foo=bar" plus random padding, which endpoints that
  // validate their input reject before the slow-body hold can bite.
  std::string body_data;
  std::string body_data_source;          // "@file" or "literal", for the report

  // Range (-R) specific knobs.
  int range_start = 5;                    // -a  left boundary of each range
  int range_limit = 2000;                 // -b  right boundary ceiling

  // Slow read (-X) specific knobs, names and defaults matching the classic tool.
  std::chrono::seconds read_interval{1};  // -n  delay between read() calls
  int read_len = 5;                       // -z  bytes per read() call
  int window_lower = 1;                   // -w  advertised window range, low end
  int window_upper = 512;                 // -y  advertised window range, high end
  int pipeline_factor = 1;                // -k  repeat the request N times

  // Proxies. -d carries everything (attack + probe); -e carries only the probe,
  // which is how you measure availability from a different network path than the
  // one being saturated.
  ProxyEndpoint proxy;                   // -d  host:port, all traffic
  ProxyEndpoint probe_proxy;             // -e  host:port, probe traffic only

  // Availability probe. `probe_timeout` keeps the classic -p meaning: how long to
  // wait for a response before calling the service unavailable.
  bool probe_enabled = true;
  std::chrono::seconds probe_timeout{5};       // -p
  std::chrono::milliseconds probe_interval{2000};  // --probe-interval
  // A probe slower than this (but still answered) counts as degraded rather than
  // served. Raised at runtime to a multiple of the measured baseline so a target
  // that is simply slow does not read as degraded from the first sample.
  std::chrono::milliseconds degraded_above{1000};

  CapacityPlan capacity;

  // Reporting.
  bool report = false;                   // -g  write a report
  std::string report_base = "slowhttptest-ng";  // -o  base name (.html/.json)
  // Fraction of probes that must be served for the JSON criterion to pass. Used
  // for CI gating; it is a stated threshold, not a claim about the target.
  double availability_threshold = 0.95;  // --availability-threshold

  // --fail-on-status: status codes that additionally fail the criterion. Affects
  // the CI gate only, never the denied/degraded/held outcome.
  StatusMatcher fail_on_status;
  std::string fail_on_status_spec;       // as typed, for the report

  int log_level = 1;                     // -v  0..4 (Fatal..Debug), classic scale
  bool verbose = false;                  // derived: log_level >= 4

  // Resolves the verb actually used given the mode when -t was not supplied.
  // Range defaults to HEAD like the classic tool: the response body is irrelevant
  // to the attack, and HEAD keeps the reply small while the server still pays the
  // full cost of processing the range set.
  std::string effective_verb() const {
    if (!verb.empty()) return verb;
    switch (mode) {
      case Mode::SlowBody: return "POST";
      case Mode::Range:    return "HEAD";
      default:             return "GET";
    }
  }

  // True if a -1 header names `name` (case-insensitively), so a default is not
  // emitted alongside the operator's own value and duplicated on the wire.
  bool has_extra_header(const std::string& name) const {
    for (const auto& h : extra_headers) {
      if (h.size() <= name.size()) continue;
      bool same = true;
      for (std::size_t i = 0; i < name.size(); ++i) {
        char a = h[i], b = name[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
        if (a != b) { same = false; break; }
      }
      if (same && h[name.size()] == ':') return true;
    }
    return false;
  }

  // Cookie, Referer and every -1 header, already CRLF-terminated and ready to
  // splice into a request. Built here rather than in each attack so the probe
  // cannot end up addressing a different endpoint than the attack does -- with
  // host-routing or tenant headers in play, that would silently measure the
  // wrong service.
  std::string caller_headers() const {
    std::string out;
    if (!cookie.empty()) out += "Cookie: " + cookie + "\r\n";
    for (const auto& h : extra_headers) out += h + "\r\n";
    // A second marker, independent of the User-Agent, carried since the classic
    // tool: whoever is on the receiving end can grep for either. Skipped when the
    // operator supplied their own -- some frameworks check Referer for same-origin
    // on POST, and a value they cannot parse would get the request rejected
    // before the slow-body hold could bite.
    if (!referer.empty() && !has_extra_header("Referer"))
      out += "Referer: " + referer + "\r\n";
    return out;
  }

  // The request-target that goes in the request line. A plain-http request sent
  // *to a proxy* must name the absolute URI (RFC 9112 §3.2.2); through a CONNECT
  // tunnel, and with no proxy at all, it is the origin-form path.
  std::string request_target() const {
    if (proxy.enabled() && !target.tls())
      return target.scheme + "://" + target.authority() + target.path;
    return target.path;
  }

  // Where the attack's TCP connections actually go, in the bare form getaddrinfo
  // wants -- no brackets, or resolution of an IPv6 literal fails.
  std::string connect_host() const {
    return proxy.enabled() ? proxy.host : target.host;
  }

  // Same endpoint, formatted for humans. An unbracketed "::1:8080" leaves the
  // reader guessing where the address stops and the port starts.
  std::string connect_endpoint() const {
    if (proxy.enabled()) return proxy.host + ":" + proxy.port;
    return target.authority();
  }
  std::string connect_port() const {
    return proxy.enabled() ? proxy.port : target.port;
  }
};

}  // namespace slowhttp

#endif  // SLOWHTTP_CONFIG_HPP_
