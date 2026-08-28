// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_EVENT_LOG_HPP_
#define SLOWHTTP_EVENT_LOG_HPP_

#include <string>
#include <vector>

namespace slowhttp {

// Availability as seen by one probe request. Three states, deliberately: "the
// server answered slowly" is a different finding from "the server did not
// answer", and collapsing them would hide the most common real-world outcome.
enum class Availability { Ok, Degraded, Denied };

const char* availability_name(Availability a);

// The conclusion of a whole run. Four states — `Inconclusive` exists so the tool
// can decline to draw a conclusion (baseline already unhealthy, too few probes)
// instead of reporting a reassuring "held" that was never actually measured.
enum class Outcome { Denied, Degraded, Held, Inconclusive };

const char* outcome_name(Outcome o);

// One availability measurement.
struct ProbeSample {
  double t = 0;          // seconds since run start
  Availability state = Availability::Ok;
  long ms = -1;          // time to first response byte; -1 when nothing came back
  std::string detail;    // "connect refused", "timeout after 5000 ms", ...

  // The HTTP status the server answered with, or -1 if it never answered. This
  // deliberately does NOT feed the availability state -- a 503 is a response,
  // and the tool says so -- but it is recorded so a reader can see it, and so
  // --fail-on-status can gate CI on it.
  int status = -1;
  bool status_fails = false;  // matched the operator's --fail-on-status spec
};

// How many connections the tool was actually holding at a moment in time. This
// is the honest denominator: `-c` is what was asked for, `held` is what existed.
struct ConnSample {
  double t = 0;
  int held = 0;
  int target = 0;
};

// A row in the human-readable event table: a state change and what triggered it.
struct Note {
  double t = 0;
  Availability state = Availability::Ok;
  std::string title;
  std::string detail;
};

// One step of a capacity staircase.
struct CapacityLevel {
  // What the level asked for, and what it actually got. These are not the same
  // thing, and conflating them is how a staircase reports a ceiling it never
  // reached: connect failures, --max-connecting, slow handshakes, peer closes
  // and local descriptor limits all leave the level short, and the probes then
  // describe whatever load was really present rather than `connections`.
  int connections = 0;    // requested
  int reached_max = 0;    // highest simultaneous connections seen while holding
  int reached_min = 0;    // lowest, so a level that drained is visible
  bool ramped = false;    // did the level actually reach `connections`?

  double hold_s = 0;
  int probes_served = 0;
  int probes_total = 0;
  long median_ms = -1;  // across served probes; -1 when none were served
  bool denied = false;

  // Set when the level never reached its target. The probes are still recorded
  // -- they are real observations -- but they say nothing about `connections`,
  // so the level must not count as either held or denied at that number.
  bool inconclusive = false;
};

// Everything about the run that the reports need, gathered once.
struct RunMeta {
  std::string tool_version;      // set from kToolVersion
  std::string started_utc;       // ISO-8601, e.g. "2026-08-10 14:22:05 UTC"
  std::string target_url;
  std::string mode_flag;         // "-X"
  std::string mode_label;        // "slow read"
  int connections = 0;           // requested (-c)
  int rate = 0;                  // -r
  long duration_s = 0;           // -l
  long interval_s = 0;           // -i
  long read_interval_s = 0;      // -n
  int read_len = 0;              // -z
  int window_lower = 0;          // -w
  int window_upper = 0;          // -y
  int kernel_rcvbuf = -1;        // what SO_RCVBUF actually became
  long probe_interval_ms = 0;
  long probe_timeout_ms = 0;
  long degraded_above_ms = 0;
  std::string tls_description;   // "TLSv1.3 / TLS_AES_256_GCM_SHA384"
  // Which protocol carried the attack, and which carried the availability
  // probe. They are not always the same: the HTTP/2 attacks speak h2 while the
  // probe is an ordinary HTTP/1.1 GET, so on an h2 run the oracle is measuring
  // a path the attack never touched. That is a real limitation of the result
  // and the report has to say so rather than let the reader assume otherwise.
  bool attack_http2 = false;
  std::string probe_protocol = "HTTP/1.1";
  std::string proxy;             // "host:port" or empty
  std::string probe_proxy;       // "host:port" or empty
  std::string fail_on_status_spec;  // --fail-on-status as typed, or empty
  // Which browser agent this run presented. Recorded because it is chosen at
  // random when -A is not given, and because CDNs and WAFs route on it -- two
  // runs that differ only here can legitimately produce different results.
  std::string user_agent;
  int extra_header_count = 0;    // how many -1 headers rode on every request
  std::string body_data_source;  // "literal", a filename, or empty
  long baseline_ms = -1;         // median probe latency before the attack
};

// The conclusion, with everything needed to defend it.
struct Verdict {
  Outcome outcome = Outcome::Inconclusive;
  std::string scope;             // "under slow read at 200 connections"
  std::string summary;           // one paragraph, plain prose

  double time_to_denial_s = -1;  // < 0 when the service never stopped answering
  double unavailable_s = 0;
  double unavailable_pct = 0;    // share of the attack window
  double recovery_s = -1;        // < 0 when it never recovered or never fell over

  int probes_total = 0;          // within the attack window
  int probes_served = 0;
  int probes_degraded = 0;
  int probes_denied = 0;
  double availability = 0;       // served / total, within the attack window
  long median_served_ms = -1;    // median latency of the probes that were served

  // Stated pass/fail for CI. This is a threshold the operator chose, not a
  // property of the target.
  double criterion_threshold = 0;
  bool criterion_pass = false;
  // Probes whose status matched --fail-on-status. Counted separately and applied
  // only to the criterion, so opting into "5xx is a failure for my pipeline"
  // never rewrites what was actually measured.
  int probes_failing_status = 0;

  // Denial threshold, only ever a bracket: lo < n <= hi.
  bool threshold_measured = false;
  int threshold_lo = 0;
  int threshold_hi = 0;
  int threshold_step = 0;
  std::string threshold_note;    // why it was not measured, when it wasn't

  std::vector<std::string> caveats;
};

// One append-only record of the run. Both renderers read from this and nothing
// else, so the HTML and the JSON cannot disagree about what happened.
class EventLog {
 public:
  RunMeta meta;
  std::vector<ProbeSample> probes;
  std::vector<ConnSample> conns;
  std::vector<Note> notes;
  std::vector<CapacityLevel> capacity;

  double attack_start_s = 0;
  double attack_end_s = 0;   // when the attack stopped applying pressure
  double run_end_s = 0;      // including post-attack recovery watching
  int exit_code = 0;

  void note(double t, Availability state, std::string title, std::string detail);

  // Records a probe result and, when the state changed, the matching Note.
  void add_probe(const ProbeSample& s);

  // Probes taken before the attack started, used as the health baseline.
  std::vector<const ProbeSample*> baseline_probes() const;

  // Derives the conclusion. `threshold` is the availability fraction the JSON
  // criterion is judged against.
  Verdict evaluate(double threshold) const;

 private:
  bool have_state_ = false;
  Availability last_state_ = Availability::Ok;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_EVENT_LOG_HPP_
