// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/cli.hpp"

#include <getopt.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace slowhttp {

const char* mode_name(Mode m) {
  switch (m) {
    case Mode::SlowHeaders: return "slow headers (Slowloris)";
    case Mode::SlowBody:    return "slow body (R-U-Dead-Yet)";
    case Mode::SlowRead:    return "slow read";
    case Mode::Range:       return "range (Apache killer)";
  }
  return "unknown";
}

void print_usage() {
  std::printf(
      "slowhttptest-ng (M0) - modern rewrite, work in progress\n"
      "Usage: slowhttptest-ng [options]\n"
      "\n"
      "Test modes:\n"
      "  -H            slow headers a.k.a. Slowloris (default)\n"
      "  -B            slow body a.k.a. R-U-Dead-Yet\n"
      "  -R            range attack a.k.a. Apache killer\n"
      "  -X            slow read\n"
      "\n"
      "General options:\n"
      "  -u URL        absolute URL of target (http://localhost/)\n"
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
      "  -1 header     raw extra header, e.g. -1 \"X-Foo: bar\"\n"
      "  -v level      verbosity 0-4: Fatal, Info, Error, Warning, Debug (1)\n"
      "  -h            this help\n"
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
      "NOTE: this is the C++ rewrite in progress. All four test modes are wired\n"
      "end-to-end; https targets still need the TLS backend (M1).\n");
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

  auto colon = authority.find(':');
  if (colon == std::string::npos) {
    out.host = authority;
    out.port = out.scheme == "https" ? "443" : "80";
  } else {
    out.host = authority.substr(0, colon);
    out.port = authority.substr(colon + 1);
    if (out.port.empty()) {
      error = "URL has ':' but no port";
      return false;
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

}  // namespace

CliResult parse_cli(int argc, char** argv, Config& cfg) {
  std::string url = "http://localhost/";
  int tmp = 0;
  int o;
  // Mirrors the classic flag set; unimplemented modes still parse so scripts and
  // help stay stable.
  optind = 1;
  while ((o = getopt(argc, argv,
                     ":HBRXhc:r:l:i:x:s:t:f:m:j:u:v:n:z:w:y:k:a:b:1:")) != -1) {
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
      case '1': cfg.extra_header = optarg; break;
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
      // Matches the classic tool: -v takes a level 0..4, not a bare flag.
      case 'v': if (!parse_int_arg(tmp, 'v', 0, 4)) return CliResult::kError;
                cfg.log_level = tmp;
                cfg.verbose = tmp >= 4; break;
      case 'h': print_usage(); return CliResult::kExit;
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

  std::string err;
  if (!parse_url(url, cfg.target, err)) {
    std::fprintf(stderr, "Error: %s\n", err.c_str());
    return CliResult::kError;
  }
  return CliResult::kRun;
}

}  // namespace slowhttp
