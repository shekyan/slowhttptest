// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the verdict logic and the two renderers. No sockets: an
// EventLog is filled in by hand, which is the whole point of routing both
// reports through one in-memory record of the run.
//
// The cases that matter most here are the ones where the tool must NOT claim
// something: an unhealthy baseline, too few samples, and a denial threshold that
// the run's resolution cannot support.
#include <cstdio>
#include <string>

#include "slowhttp/event_log.hpp"
#include "slowhttp/report.hpp"

using namespace slowhttp;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

static bool contains(const std::string& hay, const std::string& needle) {
  return hay.find(needle) != std::string::npos;
}

// A log with a baseline, an attack window, and probes supplied by the caller.
static EventLog make_log(double attack_start, double attack_end) {
  EventLog log;
  log.meta.tool_version = "2.0.0";
  log.meta.started_utc = "2026-08-10 14:22:05 UTC";
  log.meta.target_url = "http://127.0.0.1:8080/";
  log.meta.mode_flag = "-X";
  log.meta.mode_label = "slow read";
  log.meta.connections = 200;
  log.meta.rate = 50;
  log.meta.duration_s = 120;
  log.meta.probe_interval_ms = 2000;
  log.meta.probe_timeout_ms = 5000;
  log.meta.degraded_above_ms = 1000;
  log.attack_start_s = attack_start;
  log.attack_end_s = attack_end;
  log.run_end_s = attack_end + 12;
  return log;
}

static void add(EventLog& log, double t, Availability a, long ms) {
  ProbeSample s;
  s.t = t;
  s.state = a;
  s.ms = ms;
  s.detail = a == Availability::Denied ? "no response within 5000 ms" : "HTTP/1.1 200 OK";
  log.add_probe(s);
}

static void test_denied() {
  EventLog log = make_log(6, 120);
  add(log, 0, Availability::Ok, 12);
  add(log, 2, Availability::Ok, 14);
  add(log, 4, Availability::Ok, 11);
  add(log, 8, Availability::Degraded, 1180);
  for (double t = 10; t <= 120; t += 2) add(log, t, Availability::Denied, -1);
  add(log, 124, Availability::Ok, 22);
  log.conns.push_back(ConnSample{0, 0, 0});
  log.conns.push_back(ConnSample{20, 200, 200});

  const Verdict v = log.evaluate(0.95);
  check(v.outcome == Outcome::Denied, "denied run reports outcome denied");
  check(v.probes_denied > 0, "denied run counts denied probes");
  check(v.time_to_denial_s == 4, "time to denial is measured from attack start");
  check(v.recovery_s == 4, "recovery is measured from attack end");
  check(!v.criterion_pass, "a denied run fails the availability criterion");
  check(contains(v.scope, "slow read") && contains(v.scope, "200 connections"),
        "verdict is scoped to the conditions that produced it");
  // The four standing caveats must survive into every verdict.
  check(v.caveats.size() >= 4, "verdict lists what it could not rule out");

  const std::string json = render_json(log, v);
  check(contains(json, "\"outcome\": \"denied\""), "JSON carries the outcome");
  check(contains(json, "\"pass\": false"), "JSON carries a CI pass/fail");
  check(contains(json, "\"not_ruled_out\""), "JSON carries the caveats");
  check(contains(json, "\"measured\": false"),
        "JSON says the denial threshold was not measured in a plain run");

  const std::string html = render_html(log, v);
  check(contains(html, "SERVICE DENIED"), "HTML leads with the outcome");
  check(!contains(html, "VULNERABLE"),
        "HTML never frames the result as a property of the target");
  check(contains(html, "Not ruled out"), "HTML shows the caveats");
  // Self-contained: nothing may be fetched at view time. The original tool's
  // report loads Google Charts over the network and renders nothing offline.
  check(!contains(html, "<script src"), "HTML loads no external script");
  check(!contains(html, "<link"), "HTML loads no external stylesheet");
  check(!contains(html, "cdn."), "HTML references no CDN");
  check(contains(html, "window.RUN"), "HTML embeds its own run data");
}

static void test_held() {
  EventLog log = make_log(6, 120);
  for (double t = 0; t <= 130; t += 2)
    add(log, t, Availability::Ok, 12);

  const Verdict v = log.evaluate(0.95);
  check(v.outcome == Outcome::Held, "a target that answered throughout held");
  check(v.criterion_pass, "a held run passes the availability criterion");
  check(v.time_to_denial_s < 0, "no denial time when nothing was denied");
  // "Held" must stay conditional: it is not a clean bill of health.
  bool scoped = false;
  for (const auto& c : v.caveats)
    if (contains(c, "says nothing about behaviour above")) scoped = true;
  check(scoped, "a held verdict says it does not generalize past -c");
}

static void test_degraded() {
  EventLog log = make_log(6, 120);
  add(log, 0, Availability::Ok, 12);
  add(log, 2, Availability::Ok, 12);
  add(log, 4, Availability::Ok, 12);
  for (double t = 8; t <= 120; t += 2) add(log, t, Availability::Degraded, 1800);

  const Verdict v = log.evaluate(0.95);
  check(v.outcome == Outcome::Degraded,
        "answered-but-slow is degraded, not denied and not held");
  check(v.probes_denied == 0, "degraded run has no denied probes");
}

static void test_inconclusive_bad_baseline() {
  EventLog log = make_log(6, 120);
  add(log, 0, Availability::Denied, -1);  // already broken before any load
  add(log, 2, Availability::Ok, 900);
  add(log, 4, Availability::Ok, 950);
  for (double t = 8; t <= 120; t += 2) add(log, t, Availability::Denied, -1);

  const Verdict v = log.evaluate(0.95);
  check(v.outcome == Outcome::Inconclusive,
        "an unhealthy baseline makes the run inconclusive, not a finding");
  check(contains(v.summary, "before any load"),
        "the inconclusive summary says why");
}

static void test_inconclusive_too_few_probes() {
  EventLog log = make_log(6, 120);
  add(log, 0, Availability::Ok, 12);
  add(log, 8, Availability::Denied, -1);

  const Verdict v = log.evaluate(0.95);
  check(v.outcome == Outcome::Inconclusive,
        "two samples in the window is not enough to conclude anything");
  check(!v.criterion_pass,
        "too few probes must not pass the criterion by accident");
}

// A level that reached the load it asked for. Named rather than positional:
// aggregate initialisation silently changes meaning when a field is added in
// the middle of the struct, which is exactly what happened when reached_max
// and ramped landed.
static CapacityLevel level(int conns, int served, int total, long median,
                           bool denied) {
  CapacityLevel c;
  c.connections = conns;
  c.reached_max = conns;
  c.reached_min = conns;
  c.ramped = true;
  c.hold_s = 15;
  c.probes_served = served;
  c.probes_total = total;
  c.median_ms = median;
  c.denied = denied;
  return c;
}

// An HTTP/2 attack is judged by an HTTP/1.1 probe. That is a real limit on what
// the run can conclude, so it has to appear in the artifact rather than being
// left for the reader to deduce from the mode label.
static void test_http2_run_discloses_probe_protocol() {
  EventLog log = make_log(2, 100);
  log.meta.attack_http2 = true;
  log.meta.mode_label = "HTTP/2 rapid reset";
  for (double t = 0; t <= 100; t += 2) add(log, t, Availability::Ok, 20);

  const Verdict v = log.evaluate(0.95);
  bool disclosed = false;
  for (const auto& c : v.caveats)
    if (c.find("HTTP/2 path the attack used") != std::string::npos)
      disclosed = true;
  check(disclosed,
        "an HTTP/2 run says the availability oracle was not on HTTP/2");

  const std::string json = render_json(log, v);
  check(contains(json, "\"attack_protocol\": \"HTTP/2\""),
        "JSON names the attack protocol");
  check(contains(json, "\"probe_protocol\": \"HTTP/1.1\""),
        "JSON names the probe protocol separately");

  const std::string html = render_html(log, v);
  check(contains(html, "attack used HTTP/2"),
        "the HTML parameters show the probe/attack protocol mismatch");

  // An HTTP/1.1 run has no mismatch to disclose and should not carry the note.
  EventLog plain = make_log(2, 100);
  for (double t = 0; t <= 100; t += 2) add(plain, t, Availability::Ok, 20);
  const Verdict pv = plain.evaluate(0.95);
  for (const auto& c : pv.caveats)
    check(c.find("HTTP/2 path the attack used") == std::string::npos,
          "an HTTP/1.1 run does not claim a protocol mismatch");
}

static void test_capacity_bracket() {
  EventLog log = make_log(2, 100);
  for (double t = 0; t <= 100; t += 2) add(log, t, Availability::Ok, 20);
  log.capacity.push_back(level(32, 5, 5, 13, false));
  log.capacity.push_back(level(64, 5, 5, 41, false));
  log.capacity.push_back(level(96, 1, 5, 2980, true));

  const Verdict v = log.evaluate(0.95);
  check(v.threshold_measured, "a staircase run measures the denial threshold");
  check(v.threshold_lo == 64 && v.threshold_hi == 96,
        "the threshold is bracketed by the last level that held and the first "
        "that did not");
  check(v.threshold_step == 32, "the bracket reports its own resolution");

  const std::string json = render_json(log, v);
  check(contains(json, "\"lower_exclusive\": 64"), "JSON carries the bracket low");
  check(contains(json, "\"upper_inclusive\": 96"), "JSON carries the bracket high");
  check(!contains(json, "\"denial_threshold\": 96"),
        "the threshold is never reported as a point estimate");

  const std::string html = render_html(log, v);
  check(contains(html, "64 &lt; n &le; 96"), "HTML shows the bracket, not a point");
}

// A level whose connections never came up measures the load that was actually
// present, not the load it asked for. Reporting it as "held" would be the worst
// available answer: it reads as a server that coped with a level it never saw.
static void test_capacity_level_that_never_ramped() {
  EventLog log = make_log(2, 100);
  for (double t = 0; t <= 100; t += 2) add(log, t, Availability::Ok, 20);
  log.capacity.push_back(level(32, 5, 5, 13, false));

  CapacityLevel short_level;
  short_level.connections = 64;   // asked for 64
  short_level.reached_max = 41;   // never got past 41
  short_level.reached_min = 38;
  short_level.ramped = false;
  short_level.hold_s = 15;
  short_level.probes_served = 5;  // and every probe was served
  short_level.probes_total = 5;
  short_level.median_ms = 12;
  short_level.inconclusive = true;
  log.capacity.push_back(short_level);

  const Verdict v = log.evaluate(0.95);
  check(!v.threshold_measured,
        "a level that never ramped does not bracket a threshold");
  check(v.threshold_note.find("41") != std::string::npos,
        "the note says how many connections were actually established");
  check(v.threshold_note.find("not measured") != std::string::npos,
        "and says plainly that the ceiling was not measured");

  const std::string json = render_json(log, v);
  check(contains(json, "\"inconclusive\": true"),
        "JSON marks the level inconclusive");
  check(contains(json, "\"reached_max\": 41"),
        "JSON carries what was actually reached, not just what was asked for");

  const std::string html = render_html(log, v);
  check(contains(html, "inconclusive"),
        "the HTML level table says inconclusive rather than held");
}

static void test_threshold_refused_without_capacity() {
  EventLog log = make_log(2, 100);
  log.meta.rate = 50;
  log.meta.probe_interval_ms = 2000;
  for (double t = 0; t <= 100; t += 2) add(log, t, Availability::Ok, 20);

  const Verdict v = log.evaluate(0.95);
  check(!v.threshold_measured,
        "a plain run refuses to report a denial threshold");
  check(contains(v.threshold_note, "100 connections per sample"),
        "the refusal states the resolution that made it unusable");
  check(contains(v.threshold_note, "--capacity"),
        "the refusal points at the mode that can measure it");
}

// The two renderers must never disagree, which is the reason they share an
// EventLog rather than each being handed its own numbers.
static void test_renderers_agree() {
  EventLog log = make_log(6, 120);
  add(log, 0, Availability::Ok, 12);
  add(log, 2, Availability::Ok, 13);
  add(log, 4, Availability::Ok, 11);
  for (double t = 8; t <= 120; t += 2) add(log, t, Availability::Denied, -1);

  const Verdict v = log.evaluate(0.9);
  const std::string json = render_json(log, v);
  const std::string html = render_html(log, v);
  check(contains(json, std::string("\"outcome\": \"") + outcome_name(v.outcome)),
        "JSON outcome matches the verdict");
  check(contains(html, std::string("\"outcome\": \"") + outcome_name(v.outcome)),
        "HTML footer quotes the same outcome as the JSON");
  check(contains(html, "<b>" + std::to_string(v.probes_denied) + " denied</b>") &&
            contains(html, "<b>" + std::to_string(v.probes_served) + " served</b>"),
        "HTML carries the same probe counts as the verdict and the JSON");
}

// A 503 is a served response. Opting into "5xx fails my pipeline" must move the
// CI gate and nothing else -- if it could rewrite the outcome, the report would
// be describing the operator's policy rather than the target's behaviour.
static void test_fail_on_status_gates_without_rewriting() {
  EventLog log = make_log(6, 120);
  log.meta.fail_on_status_spec = "5xx";
  for (double t = 0; t <= 130; t += 2) {
    ProbeSample s;
    s.t = t;
    s.state = Availability::Ok;      // it answered, and answered quickly
    s.ms = 12;
    s.status = 503;
    s.status_fails = t >= 6;         // tagged by the engine from --fail-on-status
    s.detail = "HTTP/1.1 503 Service Unavailable";
    log.add_probe(s);
  }

  const Verdict v = log.evaluate(0.95);
  check(v.outcome == Outcome::Held,
        "a server answering 503 quickly still counts as having served");
  check(v.availability == 1.0, "availability is unaffected by the status gate");
  check(v.probes_denied == 0, "a 503 is never counted as a denial");
  check(v.probes_failing_status > 0, "status failures are counted separately");
  check(!v.criterion_pass, "the opted-in status gate fails the run");

  const std::string json = render_json(log, v);
  check(contains(json, "\"outcome\": \"held\""),
        "JSON outcome still reflects what was measured");
  check(contains(json, "\"pass\": false"), "JSON gate reflects the policy");
  check(contains(json, "\"fail_on_status\": \"5xx\""),
        "JSON echoes the spec the run was judged against");
  check(contains(json, "\"503\": "), "JSON reports the status codes seen");
  check(contains(json, "\"status\": 503"), "per-probe status is recorded");
}

// Without the flag, the same run must pass: the status must not leak into the
// gate by default.
static void test_status_ignored_by_default() {
  EventLog log = make_log(6, 120);
  for (double t = 0; t <= 130; t += 2) {
    ProbeSample s;
    s.t = t;
    s.state = Availability::Ok;
    s.ms = 12;
    s.status = 503;
    log.add_probe(s);
  }
  const Verdict v = log.evaluate(0.95);
  check(v.criterion_pass, "503s do not fail the gate unless opted into");
  check(v.probes_failing_status == 0, "nothing is tagged without the flag");
}

int main() {
  test_fail_on_status_gates_without_rewriting();
  test_status_ignored_by_default();
  test_denied();
  test_held();
  test_degraded();
  test_inconclusive_bad_baseline();
  test_inconclusive_too_few_probes();
  test_capacity_bracket();
  test_capacity_level_that_never_ramped();
  test_http2_run_discloses_probe_protocol();
  test_threshold_refused_without_capacity();
  test_renderers_agree();

  if (failures == 0) {
    std::printf("report: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "report: %d check(s) failed\n", failures);
  return 1;
}
