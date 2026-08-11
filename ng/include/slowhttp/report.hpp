// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_REPORT_HPP_
#define SLOWHTTP_REPORT_HPP_

#include <cstdio>
#include <string>

#include "slowhttp/config.hpp"
#include "slowhttp/event_log.hpp"

namespace slowhttp {

// Both renderers take the same EventLog and Verdict and nothing else, which is
// the entire reason the HTML and the JSON cannot end up telling different
// stories about the same run.

// Machine-readable companion. Carries the four-state outcome and an explicit
// pass/fail against the stated availability threshold, for CI gating.
std::string render_json(const EventLog& log, const Verdict& v);

// Self-contained HTML: inline CSS, inline SVG, inline data. No network fetches,
// so it works offline, inside Docker and on air-gapped networks -- which the
// original's Google Charts dependency does not.
std::string render_html(const EventLog& log, const Verdict& v);

// Human summary on the terminal, printed whether or not files are written.
void print_verdict(std::FILE* out, const Verdict& v, const EventLog& log);

// Writes <report_base>.html and <report_base>.json. Returns false if either
// could not be written (and says why on stderr).
bool write_reports(const Config& cfg, const EventLog& log, const Verdict& v);

}  // namespace slowhttp

#endif  // SLOWHTTP_REPORT_HPP_
