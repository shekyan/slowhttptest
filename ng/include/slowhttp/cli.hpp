// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_CLI_HPP_
#define SLOWHTTP_CLI_HPP_

#include "slowhttp/config.hpp"

namespace slowhttp {

enum class CliResult {
  kRun,    // config populated; proceed to run
  kExit,   // handled (e.g. -h): exit 0 without running
  kError,  // bad arguments: exit non-zero
};

// Parses argv (classic flag set) into cfg. Prints usage/errors to stdout/stderr.
CliResult parse_cli(int argc, char** argv, Config& cfg);

void print_usage();
void print_version();

// Parses an absolute URL (scheme://host[:port][/path]) into a Target.
bool parse_url(const std::string& url, Target& out, std::string& error);

}  // namespace slowhttp

#endif  // SLOWHTTP_CLI_HPP_
