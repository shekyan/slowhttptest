// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "slowhttp/report.hpp"

namespace slowhttp {
namespace {

std::string esc(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

std::string q(const std::string& s) { return "\"" + esc(s) + "\""; }

std::string num(double v, int decimals = 2) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%.*f", decimals, v);
  return buf;
}

// JSON has no NaN and no "unset"; null is the honest encoding for a measurement
// that did not happen, and it stops a consumer reading -1 as a real value.
std::string opt_long(long v) {
  return v < 0 ? "null" : std::to_string(v);
}
std::string opt_num(double v, int decimals = 2) {
  return v < 0 ? "null" : num(v, decimals);
}

}  // namespace

std::string render_json(const EventLog& log, const Verdict& v) {
  const RunMeta& m = log.meta;
  std::string o;
  o.reserve(8192);

  o += "{\n";
  o += "  \"tool\": \"slowhttptest-ng\",\n";
  o += "  \"version\": " + q(m.tool_version) + ",\n";
  o += "  \"schema\": 1,\n";
  o += "  \"started_utc\": " + q(m.started_utc) + ",\n";

  o += "  \"target\": {\n";
  o += "    \"url\": " + q(m.target_url) + ",\n";
  o += "    \"proxy\": " + (m.proxy.empty() ? "null" : q(m.proxy)) + ",\n";
  o += "    \"probe_proxy\": " +
       (m.probe_proxy.empty() ? "null" : q(m.probe_proxy)) + ",\n";
  o += "    \"tls\": " +
       (m.tls_description.empty() ? "null" : q(m.tls_description)) + "\n";
  o += "  },\n";

  o += "  \"parameters\": {\n";
  o += "    \"mode\": " + q(m.mode_label) + ",\n";
  o += "    \"mode_flag\": " + q(m.mode_flag) + ",\n";
  o += "    \"connections\": " + std::to_string(m.connections) + ",\n";
  o += "    \"rate_per_second\": " + std::to_string(m.rate) + ",\n";
  o += "    \"duration_seconds\": " + std::to_string(m.duration_s) + ",\n";
  o += "    \"followup_interval_seconds\": " + std::to_string(m.interval_s) + ",\n";
  o += "    \"read_interval_seconds\": " + std::to_string(m.read_interval_s) + ",\n";
  o += "    \"read_length_bytes\": " + std::to_string(m.read_len) + ",\n";
  o += "    \"window_requested_bytes\": [" + std::to_string(m.window_lower) + ", " +
       std::to_string(m.window_upper) + "],\n";
  o += "    \"window_kernel_bytes\": " + opt_long(m.kernel_rcvbuf) + ",\n";
  o += "    \"window_requested_bytes\": " + opt_long(m.window_requested) + ",\n";
  // A consumer comparing runs across platforms needs this without inferring it
  // from the two byte counts.
  o += "    \"window_overridden_by_kernel\": " +
       std::string(m.window_overridden ? "true" : "false") + ",\n";
  // Emitted for every run, not only h2 ones, so a consumer can compare the two
  // without special-casing: on an HTTP/2 attack these differ, and any
  // conclusion drawn from probe results is qualified by that.
  o += "    \"attack_protocol\": " +
       q(m.attack_http2 ? "HTTP/2" : "HTTP/1.1") + ",\n";
  o += "    \"probe_protocol\": " + q(m.probe_protocol) + ",\n";
  o += "    \"probe_interval_ms\": " + std::to_string(m.probe_interval_ms) + ",\n";
  o += "    \"probe_timeout_ms\": " + std::to_string(m.probe_timeout_ms) + ",\n";
  o += "    \"degraded_above_ms\": " + std::to_string(m.degraded_above_ms) + ",\n";
  o += "    \"user_agent\": " + q(m.user_agent) + "\n";
  o += "  },\n";

  o += "  \"result\": {\n";
  o += "    \"outcome\": " + q(outcome_name(v.outcome)) + ",\n";
  o += "    \"scope\": " + q(v.scope) + ",\n";
  o += "    \"summary\": " + q(v.summary) + ",\n";
  o += "    \"baseline_ms\": " + opt_long(m.baseline_ms) + ",\n";
  o += "    \"time_to_denial_seconds\": " + opt_num(v.time_to_denial_s) + ",\n";
  o += "    \"unavailable_seconds\": " + num(v.unavailable_s) + ",\n";
  o += "    \"unavailable_percent\": " + num(v.unavailable_pct, 1) + ",\n";
  o += "    \"recovery_seconds\": " + opt_num(v.recovery_s) + ",\n";
  o += "    \"median_served_ms\": " + opt_long(v.median_served_ms) + ",\n";
  o += "    \"probes\": {\n";
  o += "      \"total\": " + std::to_string(v.probes_total) + ",\n";
  o += "      \"served\": " + std::to_string(v.probes_served) + ",\n";
  o += "      \"degraded\": " + std::to_string(v.probes_degraded) + ",\n";
  o += "      \"denied\": " + std::to_string(v.probes_denied) + ",\n";
  o += "      \"failing_status\": " + std::to_string(v.probes_failing_status) +
       "\n";
  o += "    },\n";
  o += "    \"availability\": " + num(v.availability, 4) + ",\n";
  // Every status the target answered with, and how often. A 503 flood shows up
  // here even though it counts as "served" -- the reader gets the fact without
  // the availability measurement being bent to carry it.
  o += "    \"status_counts\": {";
  {
    std::vector<std::pair<int, int>> counts;
    for (const auto& p : log.probes) {
      if (p.status < 0) continue;
      bool found = false;
      for (auto& c : counts)
        if (c.first == p.status) { ++c.second; found = true; break; }
      if (!found) counts.push_back({p.status, 1});
    }
    std::sort(counts.begin(), counts.end());
    for (std::size_t i = 0; i < counts.size(); ++i) {
      o += (i ? ", " : "");
      o += "\"" + std::to_string(counts[i].first) + "\": " +
           std::to_string(counts[i].second);
    }
  }
  o += "}\n";
  o += "  },\n";

  // The gate a CI job reads. Both thresholds are echoed next to the boolean so a
  // failing build shows exactly what it was judged against.
  o += "  \"criterion\": {\n";
  o += "    \"availability_threshold\": " + num(v.criterion_threshold, 4) + ",\n";
  o += "    \"fail_on_status\": " +
       (m.fail_on_status_spec.empty() ? std::string("null")
                                      : q(m.fail_on_status_spec)) + ",\n";
  o += "    \"pass\": " + std::string(v.criterion_pass ? "true" : "false") + "\n";
  o += "  },\n";

  o += "  \"denial_threshold\": {\n";
  o += "    \"measured\": " +
       std::string(v.threshold_measured ? "true" : "false") + ",\n";
  if (v.threshold_measured) {
    // Always a bracket. A point estimate would imply a resolution the staircase
    // does not have.
    o += "    \"lower_exclusive\": " + std::to_string(v.threshold_lo) + ",\n";
    o += "    \"upper_inclusive\": " + std::to_string(v.threshold_hi) + ",\n";
    o += "    \"step\": " + std::to_string(v.threshold_step) + ",\n";
    o += "    \"note\": null\n";
  } else {
    o += "    \"lower_exclusive\": null,\n";
    o += "    \"upper_inclusive\": null,\n";
    o += "    \"step\": null,\n";
    o += "    \"note\": " + q(v.threshold_note) + "\n";
  }
  o += "  },\n";

  o += "  \"not_ruled_out\": [\n";
  for (std::size_t i = 0; i < v.caveats.size(); ++i)
    o += "    " + q(v.caveats[i]) + (i + 1 < v.caveats.size() ? ",\n" : "\n");
  o += "  ],\n";

  o += "  \"capacity_levels\": [\n";
  for (std::size_t i = 0; i < log.capacity.size(); ++i) {
    const auto& c = log.capacity[i];
    // `connections` is what the level asked for; `reached_*` is what it got.
    // A consumer gating on `denied` alone would read an inconclusive level as
    // "held", so `inconclusive` is emitted alongside it rather than folded in.
    o += "    {\"connections\": " + std::to_string(c.connections) +
         ", \"reached_max\": " + std::to_string(c.reached_max) +
         ", \"reached_min\": " + std::to_string(c.reached_min) +
         ", \"ramped\": " + (c.ramped ? "true" : "false") +
         ", \"held_seconds\": " + num(c.hold_s, 1) +
         ", \"probes_served\": " + std::to_string(c.probes_served) +
         ", \"probes_total\": " + std::to_string(c.probes_total) +
         ", \"median_ms\": " + opt_long(c.median_ms) +
         ", \"inconclusive\": " + (c.inconclusive ? "true" : "false") +
         ", \"denied\": " + (c.denied ? "true" : "false") + "}";
    o += (i + 1 < log.capacity.size() ? ",\n" : "\n");
  }
  o += "  ],\n";

  o += "  \"timeline\": {\n";
  o += "    \"attack_start_seconds\": " + num(log.attack_start_s) + ",\n";
  o += "    \"attack_end_seconds\": " + num(log.attack_end_s) + ",\n";
  o += "    \"run_end_seconds\": " + num(log.run_end_s) + ",\n";

  o += "    \"probes\": [\n";
  for (std::size_t i = 0; i < log.probes.size(); ++i) {
    const auto& p = log.probes[i];
    o += "      {\"t\": " + num(p.t) + ", \"state\": " +
         q(availability_name(p.state)) + ", \"ms\": " + opt_long(p.ms) +
         ", \"status\": " + (p.status < 0 ? "null" : std::to_string(p.status)) +
         ", \"status_fails\": " + (p.status_fails ? "true" : "false") +
         ", \"detail\": " + q(p.detail) + "}";
    o += (i + 1 < log.probes.size() ? ",\n" : "\n");
  }
  o += "    ],\n";

  o += "    \"connections\": [\n";
  for (std::size_t i = 0; i < log.conns.size(); ++i) {
    const auto& c = log.conns[i];
    o += "      {\"t\": " + num(c.t) + ", \"held\": " + std::to_string(c.held) +
         ", \"target\": " + std::to_string(c.target) + "}";
    o += (i + 1 < log.conns.size() ? ",\n" : "\n");
  }
  o += "    ],\n";

  o += "    \"events\": [\n";
  for (std::size_t i = 0; i < log.notes.size(); ++i) {
    const auto& n = log.notes[i];
    o += "      {\"t\": " + num(n.t) + ", \"state\": " +
         q(availability_name(n.state)) + ", \"event\": " + q(n.title) +
         ", \"detail\": " + q(n.detail) + "}";
    o += (i + 1 < log.notes.size() ? ",\n" : "\n");
  }
  o += "    ]\n";
  o += "  },\n";

  o += "  \"exit_code\": " + std::to_string(log.exit_code) + "\n";
  o += "}\n";
  return o;
}

}  // namespace slowhttp
