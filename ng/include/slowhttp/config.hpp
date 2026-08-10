// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_CONFIG_HPP_
#define SLOWHTTP_CONFIG_HPP_

#include <chrono>
#include <string>

namespace slowhttp {

enum class Mode { SlowHeaders, SlowBody, SlowRead, Range };

const char* mode_name(Mode m);

// Parsed target endpoint. M0 supports plain http; https is parsed and rejected
// with a clear message until the TLS backend lands (M1).
struct Target {
  std::string scheme = "http";
  std::string host;
  std::string port = "80";
  std::string path = "/";

  bool tls() const { return scheme == "https"; }
};

// Full test configuration. Field names mirror the classic CLI flags so the flag
// parser stays a thin mapping and existing muscle memory carries over.
struct Config {
  Target target;
  Mode mode = Mode::SlowHeaders;

  int connections = 50;                  // -c  target concurrent connections
  int rate = 50;                         // -r  new connections per second
  std::chrono::seconds duration{240};    // -l  total test length
  std::chrono::seconds interval{10};     // -i  followup dribble interval
  int max_random_data_len = 32;          // -x  max size of each random name/value
  int content_length = 4096;             // -s  Content-Length for body modes

  std::string verb;                      // -t  (defaults per mode)
  std::string user_agent = "Mozilla/5.0 (X11; slowhttptest-ng)";
  std::string content_type =             // -f
      "application/x-www-form-urlencoded";
  std::string accept =                   // -m
      "text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5";
  std::string cookie;                    // -j
  std::string extra_header;              // -1  raw "Name: value"

  // Range (-R) specific knobs.
  int range_start = 5;                    // -a  left boundary of each range
  int range_limit = 2000;                 // -b  right boundary ceiling

  // Slow read (-X) specific knobs, names and defaults matching the classic tool.
  std::chrono::seconds read_interval{1};  // -n  delay between read() calls
  int read_len = 5;                       // -z  bytes per read() call
  int window_lower = 1;                   // -w  advertised window range, low end
  int window_upper = 512;                 // -y  advertised window range, high end
  int pipeline_factor = 1;                // -k  repeat the request N times

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
};

}  // namespace slowhttp

#endif  // SLOWHTTP_CONFIG_HPP_
