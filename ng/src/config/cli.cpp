// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/cli.hpp"

#include <getopt.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>

#include "slowhttp/reactor.hpp"
#include "slowhttp/tls.hpp"

namespace slowhttp {

// Supplied by CMake from project(VERSION). The fallback only applies to builds
// that bypass the build system entirely.
#ifndef SLOWHTTP_VERSION
#define SLOWHTTP_VERSION "0.0.0-unknown"
#endif

const char* const kToolVersion = SLOWHTTP_VERSION;
const char* const kProjectUrl = "https://github.com/shekyan/slowhttptest";

// "Mozilla/5.0 (compatible; ...)" is the shape well-behaved crawlers have used
// for decades (Googlebot and friends). The Mozilla token keeps servers that
// sniff for it from taking a different code path; everything after it is the
// truth about who is calling.
//
// Assembled once at startup rather than as a literal, so the version cannot
// drift from the one CMake set.
const std::string kDefaultUserAgentStorage =
    std::string("Mozilla/5.0 (compatible; slowhttptest-ng/") + kToolVersion +
    "; +" + kProjectUrl + ")";
const char* const kDefaultUserAgent = kDefaultUserAgentStorage.c_str();

// Kept deliberately short and current. Chrome and Firefox freeze the minor
// version fields at zero, and Safari's WebKit build string has been stable for
// years -- these are the shapes a real browser sends today.
const char* const kUserAgents[3] = {
    // Chrome, Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Chrome/140.0.0.0 Safari/537.36",
    // Firefox, Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 "
    "Firefox/141.0",
    // Safari, macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.5 Safari/605.1.15",
};

const char* mode_name(Mode m) {
  switch (m) {
    case Mode::SlowHeaders: return "slow headers (Slowloris)";
    case Mode::SlowBody:    return "slow body (R-U-Dead-Yet)";
    case Mode::SlowRead:    return "slow read";
    case Mode::Range:       return "range (Apache killer)";
  }
  return "unknown";
}

void print_version() {
  // Packagers and bug reports need to know whether TLS is compiled in; a build
  // without it behaves differently in a way that is otherwise invisible.
  std::printf("slowhttptest-ng %s\n%s\nTLS: %s\n", kToolVersion, kProjectUrl,
              TlsContext::available() ? "enabled (OpenSSL)"
                                      : "disabled (built with -DSLOWHTTP_TLS=OFF)");
  // The connection ceiling belongs here too: on some platforms it is a fixed
  // property of the reactor backend rather than something -c or ulimit controls,
  // and finding that out by hitting it is a bad way to learn.
  const std::size_t cap = Reactor::create()->max_descriptors();
  if (cap > 0)
    std::printf("reactor: poll, max %zu connections (fixed OPEN_MAX ceiling)\n",
                cap);
  else
    std::printf("reactor: poll, bounded by the file descriptor limit\n");
}

void print_usage() {
  std::printf(
      "slowhttptest-ng %s - modern C++ rewrite of slowhttptest\n"
      "Usage: slowhttptest-ng [options]\n",
      kToolVersion);
  std::printf(
      "\n"
      "Test modes:\n"
      "  -H            slow headers a.k.a. Slowloris (default)\n"
      "  -B            slow body a.k.a. R-U-Dead-Yet\n"
      "  -R            range attack a.k.a. Apache killer\n"
      "  -X            slow read\n"
      "\n"
      "General options:\n"
      "  -u URL        absolute URL of target, http or https (http://localhost/)\n"
      "  -c num        target number of connections (50)\n"
      "  -r rate       new connections per second (50)\n"
      "  -l seconds    test length in seconds (240)\n"
      "  -i seconds    interval between followup data (10)\n"
      "  -x bytes      max length of each random name/value pair (32)\n"
      "  -s bytes      Content-Length header value for body modes (4096)\n"
      "  -t verb       request verb (GET for headers/read, POST for body)\n"
      "  -f type       Content-Type header value\n"
      "  -m accept     Accept header value\n"
      "  -j cookie     Cookie header value\n"
      "  --no-referer  do not send the Referer header. It is sent by default as\n"
      "                \"TESTING_PURPOSES_ONLY\" so the traffic is recognisable;\n"
      "                drop it if the target rejects an unparseable Referer, or\n"
      "                replace it with -1 \"Referer: https://...\"\n"
      "  -1 header     extra header, repeatable. Also --header.\n"
      "                e.g. -1 \"Authorization: Bearer abc\" -1 \"X-Tenant: acme\"\n"
      "                Sent on every attack request AND on the probe, so both\n"
      "                reach the same endpoint.\n"
      "  -P data       request body for -B; @file reads it from a file.\n"
      "                Also --data. e.g. -P '{\"a\":1}' or -P @payload.json\n"
      "  -A ua         User-Agent header. Also --user-agent. By default the tool\n"
      "                identifies itself, so the traffic is recognisable in the\n"
      "                target's own logs.\n"
      "  --random-user-agent   present as Chrome, Firefox or Safari instead (one\n"
      "                picked per run). Use when a WAF sheds the tool's own agent\n"
      "                before it reaches the service; the report records which.\n"
      "  -v level      verbosity 0-4, on the classic scale (1). What differs:\n"
      "                0 silent (same as -q), 1 normal, 4 adds a breakdown of\n"
      "                connect failures by cause\n"
      "  -q            quiet: no console output at all. Same as -v 0. Reports are\n"
      "                still written; errors and the exit code still speak.\n"
      "                Also --quiet.\n"
      "  -h            this help. Also --help.\n"
      "  -V            version, project URL and whether TLS is compiled in.\n"
      "                Also --version.\n"
      "\n"
      "Proxy options:\n"
      "  -d host:port  route all traffic through this HTTP proxy\n"
      "  -e host:port  route only the availability probe through this proxy,\n"
      "                to measure availability from a different network path\n"
      "                than the one being saturated\n"
      "\n"
      "Availability probe (this is what the verdict is based on):\n"
      "  -p seconds    probe timeout; no response within this = unavailable (5)\n"
      "  --probe-interval SEC   seconds between probes (2)\n"
      "  --no-probe    do not measure availability at all (no verdict, no report)\n"
      "\n"
      "Capacity search - brackets the denial threshold instead of guessing it:\n"
      "  --capacity            hold connections at each level, probe, then step up\n"
      "  --capacity-start N    first level (32)\n"
      "  --capacity-step N     increment between levels (32)\n"
      "  --capacity-max N      ceiling (defaults to -c)\n"
      "  --capacity-hold SEC   seconds held at each level (15)\n"
      "\n"
      "Reporting:\n"
      "  -g            write a report (self-contained HTML + JSON)\n"
      "  -o base       report base name; writes base.html and base.json\n"
      "                (slowhttptest-ng)\n"
      "  --availability-threshold F   fraction of probes that must be served for\n"
      "                the JSON criterion to pass, for CI gating (0.95)\n"
      "  --fail-on-status LIST   status codes that also fail the CI criterion,\n"
      "                e.g. 5xx or \"503,429\". Affects the pass/fail gate only:\n"
      "                a 503 is still a served response, and the measured\n"
      "                outcome never pretends otherwise.\n"
      "\n"
      "Range (-R) options:\n"
      "  -a start      left boundary of the ranges in the Range header (5)\n"
      "  -b bytes      ceiling for the Range header right boundary (2000)\n"
      "\n"
      "Slow read (-X) options:\n"
      "  -n seconds    interval between read() calls on the recv buffer (1)\n"
      "  -z bytes      bytes to read from the recv buffer per read() call (5)\n"
      "  -w bytes      advertised window range, low end (1)\n"
      "  -y bytes      advertised window range, high end (512)\n"
      "  -k num        repeat the request N times per connection, to multiply\n"
      "                the response size on keep-alive servers (1)\n"
      "\n"
      "Client certificates for https targets are read from the SSL_CERT and\n"
      "SSL_KEY environment variables, as in the classic tool.\n"
      "\n"
      "Run only against systems you are authorized to test.\n");
}

bool parse_url(const std::string& url, Target& out, std::string& error) {
  std::string s = url;
  auto scheme_end = s.find("://");
  if (scheme_end == std::string::npos) {
    error = "URL must include a scheme, e.g. http://host/path";
    return false;
  }
  out.scheme = s.substr(0, scheme_end);
  if (out.scheme != "http" && out.scheme != "https") {
    error = "unsupported scheme '" + out.scheme + "' (expected http or https)";
    return false;
  }
  std::string rest = s.substr(scheme_end + 3);

  std::string authority;
  auto slash = rest.find('/');
  if (slash == std::string::npos) {
    authority = rest;
    out.path = "/";
  } else {
    authority = rest.substr(0, slash);
    out.path = rest.substr(slash);
  }
  if (authority.empty()) {
    error = "URL is missing a host";
    return false;
  }

  const std::string default_port = out.scheme == "https" ? "443" : "80";

  if (authority[0] == '[') {
    // IPv6 literal: the address is full of colons, so the host must be taken
    // from inside the brackets before looking for a port separator (RFC 3986
    // §3.2.2). Splitting on the first colon turns "[::1]:8080" into host "["
    // and a nonsense port.
    const auto close = authority.find(']');
    if (close == std::string::npos) {
      error = "URL has '[' but no matching ']' around the IPv6 address";
      return false;
    }
    out.host = authority.substr(1, close - 1);  // brackets are URL syntax only
    const std::string rest_of_authority = authority.substr(close + 1);
    if (rest_of_authority.empty()) {
      out.port = default_port;
    } else if (rest_of_authority[0] == ':') {
      out.port = rest_of_authority.substr(1);
      if (out.port.empty()) {
        error = "URL has ':' but no port";
        return false;
      }
    } else {
      error = "unexpected text after the IPv6 address in the URL";
      return false;
    }
  } else {
    auto colon = authority.find(':');
    if (colon == std::string::npos) {
      out.host = authority;
      out.port = default_port;
    } else {
      out.host = authority.substr(0, colon);
      out.port = authority.substr(colon + 1);
      if (out.port.empty()) {
        error = "URL has ':' but no port";
        return false;
      }
    }
  }
  if (out.host.empty()) {
    error = "URL is missing a host";
    return false;
  }
  return true;
}

namespace {

// Parses optarg as an int in [min, max]; returns false and reports on error.
// The flag character is passed explicitly: POSIX only guarantees `optopt` is set
// when getopt reports an error, so reading it for a *valid* option is undefined.
bool parse_int_arg(int& val, char flag, long min, long max) {
  char* end = nullptr;
  long tmp = std::strtol(optarg, &end, 10);
  if (end == optarg || *end != '\0' || tmp < min || tmp > max) {
    std::fprintf(stderr,
                 "Error: invalid value '%s' for -%c (expected %ld..%ld)\n",
                 optarg, flag, min, max);
    return false;
  }
  val = static_cast<int>(tmp);
  return true;
}

bool parse_positive(int& val, char flag, long max = 2147483647L) {
  return parse_int_arg(val, flag, 1, max);
}

bool parse_fraction(double& val, const char* name) {
  char* end = nullptr;
  double tmp = std::strtod(optarg, &end);
  if (end == optarg || *end != '\0' || tmp < 0.0 || tmp > 1.0) {
    std::fprintf(stderr,
                 "Error: invalid value '%s' for --%s (expected 0.0..1.0)\n",
                 optarg, name);
    return false;
  }
  val = tmp;
  return true;
}

// Accepts "host:port". The port is required: a proxy on an implied port is a
// guess, and guessing wrong sends the whole test somewhere silent.
bool parse_endpoint(ProxyEndpoint& out, char flag) {
  const std::string s = optarg;
  const auto colon = s.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 == s.size()) {
    std::fprintf(stderr,
                 "Error: -%c expects host:port (got '%s')\n", flag, optarg);
    return false;
  }
  out.host = s.substr(0, colon);
  out.port = s.substr(colon + 1);
  for (char c : out.port) {
    if (c < '0' || c > '9') {
      std::fprintf(stderr, "Error: -%c port '%s' is not a number\n", flag,
                   out.port.c_str());
      return false;
    }
  }
  return true;
}

// A header the caller supplies is spliced straight into the request, so a value
// containing CR or LF would let it inject additional headers -- or an entire
// second request -- into every connection. Reject rather than silently strip:
// quietly sending something different from what was asked for is worse.
bool valid_header(const std::string& h, std::string& error) {
  if (h.find('\r') != std::string::npos || h.find('\n') != std::string::npos) {
    error = "header must not contain CR or LF: '" + h + "'";
    return false;
  }
  const auto colon = h.find(':');
  if (colon == std::string::npos || colon == 0) {
    error = "header must look like 'Name: value' (got '" + h + "')";
    return false;
  }
  return true;
}

// "5xx", "503", or a comma-separated mix of both.
bool parse_status_spec(const std::string& spec, StatusMatcher& out,
                       std::string& error) {
  std::size_t start = 0;
  while (start <= spec.size()) {
    auto comma = spec.find(',', start);
    if (comma == std::string::npos) comma = spec.size();
    std::string tok = spec.substr(start, comma - start);
    start = comma + 1;
    // Trim surrounding spaces so "-​-fail-on-status 5xx, 429" works.
    while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
    while (!tok.empty() && tok.back() == ' ') tok.pop_back();
    if (tok.empty()) continue;

    if (tok.size() == 3 && tok[0] >= '1' && tok[0] <= '5' &&
        (tok[1] == 'x' || tok[1] == 'X') && (tok[2] == 'x' || tok[2] == 'X')) {
      out.classes.push_back(tok[0] - '0');
      continue;
    }
    if (tok.size() == 3 && tok.find_first_not_of("0123456789") ==
                               std::string::npos) {
      const int code = std::atoi(tok.c_str());
      if (code >= 100 && code <= 599) {
        out.exact.push_back(code);
        continue;
      }
    }
    error = "expected a status code or class like '503' or '5xx' (got '" + tok +
            "')";
    return false;
  }
  if (out.empty()) {
    error = "no status codes given";
    return false;
  }
  return true;
}

// Reads a -P argument: literal text, or the contents of a file when it starts
// with '@', matching curl's --data convention.
bool load_body_data(const std::string& arg, Config& cfg, std::string& error) {
  if (arg.empty() || arg[0] != '@') {
    cfg.body_data = arg;
    cfg.body_data_source = "literal";
    return true;
  }
  const std::string path = arg.substr(1);
  std::FILE* fp = std::fopen(path.c_str(), "rb");
  if (!fp) {
    error = "cannot open body file '" + path + "'";
    return false;
  }
  std::string data;
  char buf[8192];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), fp)) > 0) data.append(buf, n);
  const bool bad = std::ferror(fp) != 0;
  std::fclose(fp);
  if (bad) {
    error = "error reading body file '" + path + "'";
    return false;
  }
  cfg.body_data = std::move(data);
  cfg.body_data_source = path;
  return true;
}

// Long-option identifiers, kept out of the char range used by short flags.
enum {
  kOptProbeInterval = 256,
  kOptNoProbe,
  kOptCapacity,
  kOptCapacityStart,
  kOptCapacityStep,
  kOptCapacityMax,
  kOptCapacityHold,
  kOptAvailabilityThreshold,
  kOptFailOnStatus,
  kOptRandomUserAgent,
  kOptNoReferer,
};

const struct option kLongOptions[] = {
    {"header", required_argument, nullptr, '1'},
    {"data", required_argument, nullptr, 'P'},
    {"user-agent", required_argument, nullptr, 'A'},
    {"random-user-agent", no_argument, nullptr, kOptRandomUserAgent},
    {"no-referer", no_argument, nullptr, kOptNoReferer},
    {"quiet", no_argument, nullptr, 'q'},
    {"version", no_argument, nullptr, 'V'},
    {"help", no_argument, nullptr, 'h'},
    {"fail-on-status", required_argument, nullptr, kOptFailOnStatus},
    {"probe-interval", required_argument, nullptr, kOptProbeInterval},
    {"no-probe", no_argument, nullptr, kOptNoProbe},
    {"capacity", no_argument, nullptr, kOptCapacity},
    {"capacity-start", required_argument, nullptr, kOptCapacityStart},
    {"capacity-step", required_argument, nullptr, kOptCapacityStep},
    {"capacity-max", required_argument, nullptr, kOptCapacityMax},
    {"capacity-hold", required_argument, nullptr, kOptCapacityHold},
    {"availability-threshold", required_argument, nullptr,
     kOptAvailabilityThreshold},
    {nullptr, 0, nullptr, 0},
};

// Long options report their own name in argv rather than via optopt, so errors
// are phrased with the spelling the user actually typed.
bool parse_long_int(int& val, const char* name, long min, long max) {
  char* end = nullptr;
  long tmp = std::strtol(optarg, &end, 10);
  if (end == optarg || *end != '\0' || tmp < min || tmp > max) {
    std::fprintf(stderr,
                 "Error: invalid value '%s' for --%s (expected %ld..%ld)\n",
                 optarg, name, min, max);
    return false;
  }
  val = static_cast<int>(tmp);
  return true;
}

}  // namespace

CliResult parse_cli(int argc, char** argv, Config& cfg) {
  std::string url = "http://localhost/";
  int tmp = 0;
  int o;
  // Mirrors the classic flag set; unimplemented modes still parse so scripts and
  // help stay stable.
  optind = 1;
  while ((o = getopt_long(
              argc, argv,
              ":HBRXghqVc:r:l:i:x:s:t:f:m:j:u:v:n:z:w:y:k:a:b:1:d:e:p:o:P:A:",
              kLongOptions, nullptr)) != -1) {
    switch (o) {
      case 'H': cfg.mode = Mode::SlowHeaders; break;
      case 'B': cfg.mode = Mode::SlowBody; break;
      case 'R': cfg.mode = Mode::Range; break;
      case 'X': cfg.mode = Mode::SlowRead; break;
      case 'u': url = optarg; break;
      case 'c': if (!parse_positive(tmp, 'c', 1048576)) return CliResult::kError;
                cfg.connections = tmp; break;
      case 'r': if (!parse_positive(tmp, 'r', 100000)) return CliResult::kError;
                cfg.rate = tmp; break;
      case 'l': if (!parse_positive(tmp, 'l')) return CliResult::kError;
                cfg.duration = std::chrono::seconds(tmp); break;
      case 'i': if (!parse_positive(tmp, 'i')) return CliResult::kError;
                cfg.interval = std::chrono::seconds(tmp); break;
      case 'x': if (!parse_positive(tmp, 'x')) return CliResult::kError;
                cfg.max_random_data_len = tmp < 2 ? 2 : tmp; break;
      case 's': if (!parse_positive(tmp, 's')) return CliResult::kError;
                cfg.content_length = tmp; break;
      case 't': cfg.verb = optarg; break;
      case 'f': cfg.content_type = optarg; break;
      case 'm': cfg.accept = optarg; break;
      case 'j': cfg.cookie = optarg; break;
      case 'A': cfg.user_agent = optarg; break;
      case kOptRandomUserAgent: cfg.random_user_agent = true; break;
      case kOptNoReferer: cfg.referer.clear(); break;
      // Same state as -v 0, spelled the way people look for it.
      case 'q': cfg.log_level = 0; cfg.verbose = false; break;
      case '1': {
        // Repeatable, unlike the classic single-slot -1: real targets routinely
        // need an Authorization header *and* a routing header.
        std::string herr;
        if (!valid_header(optarg, herr)) {
          std::fprintf(stderr, "Error: %s\n", herr.c_str());
          return CliResult::kError;
        }
        cfg.extra_headers.push_back(optarg);
        break;
      }
      case 'P': {
        std::string derr;
        if (!load_body_data(optarg, cfg, derr)) {
          std::fprintf(stderr, "Error: %s\n", derr.c_str());
          return CliResult::kError;
        }
        break;
      }
      case kOptFailOnStatus: {
        std::string serr;
        cfg.fail_on_status = StatusMatcher{};
        if (!parse_status_spec(optarg, cfg.fail_on_status, serr)) {
          std::fprintf(stderr, "Error: --fail-on-status: %s\n", serr.c_str());
          return CliResult::kError;
        }
        cfg.fail_on_status_spec = optarg;
        break;
      }
      case 'a': if (!parse_positive(tmp, 'a', 65539)) return CliResult::kError;
                cfg.range_start = tmp; break;
      case 'b': if (!parse_positive(tmp, 'b', 524288)) return CliResult::kError;
                cfg.range_limit = tmp; break;
      case 'n': if (!parse_positive(tmp, 'n')) return CliResult::kError;
                cfg.read_interval = std::chrono::seconds(tmp); break;
      case 'z': if (!parse_positive(tmp, 'z', 1048576)) return CliResult::kError;
                cfg.read_len = tmp; break;
      case 'w': if (!parse_positive(tmp, 'w', 1048576)) return CliResult::kError;
                cfg.window_lower = tmp; break;
      case 'y': if (!parse_positive(tmp, 'y', 1048576)) return CliResult::kError;
                cfg.window_upper = tmp; break;
      case 'k': if (!parse_positive(tmp, 'k', 1024)) return CliResult::kError;
                cfg.pipeline_factor = tmp; break;
      case 'd': if (!parse_endpoint(cfg.proxy, 'd')) return CliResult::kError;
                break;
      case 'e': if (!parse_endpoint(cfg.probe_proxy, 'e')) return CliResult::kError;
                break;
      case 'p': if (!parse_positive(tmp, 'p', 3600)) return CliResult::kError;
                cfg.probe_timeout = std::chrono::seconds(tmp); break;
      case 'g': cfg.report = true; break;
      case 'o': cfg.report_base = optarg; break;

      case kOptProbeInterval: {
        // Sub-second probing is allowed: at high connection rates a 2 s grid is
        // coarser than the ramp it is meant to observe.
        char* end = nullptr;
        double secs = std::strtod(optarg, &end);
        if (end == optarg || *end != '\0' || secs < 0.05 || secs > 3600.0) {
          std::fprintf(stderr,
                       "Error: invalid value '%s' for --probe-interval"
                       " (expected 0.05..3600 seconds)\n", optarg);
          return CliResult::kError;
        }
        cfg.probe_interval =
            std::chrono::milliseconds(static_cast<long>(secs * 1000));
        break;
      }
      case kOptNoProbe: cfg.probe_enabled = false; break;
      case kOptCapacity: cfg.capacity.enabled = true; break;
      case kOptCapacityStart:
        if (!parse_long_int(tmp, "capacity-start", 1, 1048576))
          return CliResult::kError;
        cfg.capacity.start = tmp; break;
      case kOptCapacityStep:
        if (!parse_long_int(tmp, "capacity-step", 1, 1048576))
          return CliResult::kError;
        cfg.capacity.step = tmp; break;
      case kOptCapacityMax:
        if (!parse_long_int(tmp, "capacity-max", 1, 1048576))
          return CliResult::kError;
        cfg.capacity.max = tmp; break;
      case kOptCapacityHold:
        if (!parse_long_int(tmp, "capacity-hold", 1, 86400))
          return CliResult::kError;
        cfg.capacity.hold = std::chrono::seconds(tmp); break;
      case kOptAvailabilityThreshold:
        if (!parse_fraction(cfg.availability_threshold,
                            "availability-threshold"))
          return CliResult::kError;
        break;

      // Matches the classic tool: -v takes a level 0..4, not a bare flag.
      case 'v': if (!parse_int_arg(tmp, 'v', 0, 4)) return CliResult::kError;
                cfg.log_level = tmp;
                cfg.verbose = tmp >= 4; break;
      case 'h': print_usage(); return CliResult::kExit;
      case 'V': print_version(); return CliResult::kExit;
      case ':':
        std::fprintf(stderr, "Error: option -%c requires an argument\n", optopt);
        return CliResult::kError;
      case '?':
      default:
        std::fprintf(stderr, "Error: unknown option -%c\n", optopt);
        return CliResult::kError;
    }
  }
  if (optind < argc) {
    std::fprintf(stderr, "Error: unexpected argument '%s'\n", argv[optind]);
    return CliResult::kError;
  }

  // Same guard the classic tool applies: an inverted window range would silently
  // produce nonsense rather than an empty range.
  if (cfg.window_lower > cfg.window_upper) {
    std::fprintf(stderr,
                 "Error: advertised window range start (-w %d) is above its"
                 " end (-y %d)\n",
                 cfg.window_lower, cfg.window_upper);
    return CliResult::kError;
  }

  if (!cfg.body_data.empty()) {
    if (cfg.mode != Mode::SlowBody) {
      // Nothing else ever sends a body, so a payload here would be silently
      // discarded -- and the user would reasonably believe it had been sent.
      std::fprintf(stderr,
                   "Error: -P/--data supplies a request body, which only the"
                   " slow body mode (-B) sends\n");
      return CliResult::kError;
    }
    // The attack works by promising more body than it delivers. A payload at or
    // past the promise would complete the request, the server would answer, and
    // the hold would end -- so the promise is raised to keep it a hold.
    const long need = static_cast<long>(cfg.body_data.size()) + 4096;
    if (need > cfg.content_length) {
      if (cfg.log_level >= 1)
        std::fprintf(stderr,
                     "Note: raising -s from %d to %ld so the %zu-byte body from"
                     " -P stays unfinished\n",
                     cfg.content_length, need, cfg.body_data.size());
      cfg.content_length = static_cast<int>(need);
    }
  }

  // The verdict, the report and the capacity search are all built on probe
  // results. Silently producing an empty report would be worse than refusing.
  if (!cfg.probe_enabled && cfg.report) {
    std::fprintf(stderr,
                 "Error: -g asks for a report, but --no-probe removes the"
                 " availability measurement the report is made of\n");
    return CliResult::kError;
  }
  if (!cfg.probe_enabled && cfg.capacity.enabled) {
    std::fprintf(stderr,
                 "Error: --capacity finds the level at which service is denied,"
                 " which needs the probe that --no-probe disables\n");
    return CliResult::kError;
  }

  if (cfg.capacity.enabled) {
    if (cfg.capacity.max == 0) cfg.capacity.max = cfg.connections;
    if (cfg.capacity.max < cfg.capacity.start) {
      std::fprintf(stderr,
                   "Error: --capacity-max %d is below --capacity-start %d\n",
                   cfg.capacity.max, cfg.capacity.start);
      return CliResult::kError;
    }
    // The connection pool is sized once from -c, so the ceiling has to fit in it.
    if (cfg.capacity.max > cfg.connections) {
      if (cfg.log_level >= 1)
        std::fprintf(stderr,
                     "Note: raising -c from %d to %d so the staircase can reach"
                     " --capacity-max\n",
                     cfg.connections, cfg.capacity.max);
      cfg.connections = cfg.capacity.max;
    }
  }

  // A probe that fires faster than it can time out would overlap itself; the
  // prober only runs one at a time, so the effective interval would silently
  // become the timeout instead of what was asked for.
  if (cfg.probe_enabled &&
      cfg.probe_interval < std::chrono::duration_cast<std::chrono::milliseconds>(
                               cfg.probe_timeout)) {
    // Not an error: this is the useful configuration when the target is healthy,
    // and the sampling grid only stretches while it is not.
    if (cfg.log_level >= 4) {
      std::fprintf(stderr,
                   "Note: --probe-interval is shorter than -p, so during an"
                   " outage samples will be spaced by the %llds timeout\n",
                   static_cast<long long>(cfg.probe_timeout.count()));
    }
  }

  // Both name the agent, so accepting both would mean silently ignoring one.
  if (cfg.random_user_agent && !cfg.user_agent.empty()) {
    std::fprintf(stderr,
                 "Error: -A names a User-Agent and --random-user-agent picks"
                 " one; use one or the other\n");
    return CliResult::kError;
  }
  if (cfg.user_agent.empty()) {
    if (cfg.random_user_agent) {
      // One per run, not per connection: see kUserAgents.
      std::mt19937 rng(std::random_device{}());
      std::uniform_int_distribution<int> pick(0, kUserAgentCount - 1);
      cfg.user_agent = kUserAgents[pick(rng)];
    } else {
      cfg.user_agent = kDefaultUserAgent;
    }
  }

  std::string err;
  if (!parse_url(url, cfg.target, err)) {
    std::fprintf(stderr, "Error: %s\n", err.c_str());
    return CliResult::kError;
  }
  return CliResult::kRun;
}

}  // namespace slowhttp
