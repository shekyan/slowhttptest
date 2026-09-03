// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/event_log.hpp"

#include <algorithm>
#include <cstdio>
#include <utility>

namespace slowhttp {
namespace {

// Below this many probes inside the attack window there is not enough evidence
// to call anything, in either direction.
constexpr int kMinProbesForVerdict = 3;

// Share of answered-but-slow probes above which a run that never saw a hard
// denial is still reported as degraded rather than held.
constexpr double kDegradedShare = 0.25;

long median_of(std::vector<long> v) {
  if (v.empty()) return -1;
  std::sort(v.begin(), v.end());
  return v[v.size() / 2];
}

std::string fmt(const char* f, double v) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), f, v);
  return buf;
}

}  // namespace

const char* availability_name(Availability a) {
  switch (a) {
    case Availability::Ok:       return "served";
    case Availability::Degraded: return "degraded";
    case Availability::Denied:   return "denied";
  }
  return "unknown";
}

const char* outcome_name(Outcome o) {
  switch (o) {
    case Outcome::Denied:       return "denied";
    case Outcome::Degraded:     return "degraded";
    case Outcome::Held:         return "held";
    case Outcome::Inconclusive: return "inconclusive";
  }
  return "unknown";
}

void EventLog::note(double t, Availability state, std::string title,
                    std::string detail) {
  notes.push_back(Note{t, state, std::move(title), std::move(detail)});
}

void EventLog::add_probe(const ProbeSample& s) {
  probes.push_back(s);
  if (!have_state_ || s.state != last_state_) {
    const char* title = "Probe";
    switch (s.state) {
      case Availability::Ok:
        title = have_state_ ? "Service restored" : "Baseline established";
        break;
      case Availability::Degraded:
        title = "Probe slowed";
        break;
      case Availability::Denied:
        title = "Service denied";
        break;
    }
    note(s.t, s.state, title, s.detail);
    have_state_ = true;
    last_state_ = s.state;
  }
}

std::vector<const ProbeSample*> EventLog::baseline_probes() const {
  std::vector<const ProbeSample*> out;
  for (const auto& p : probes)
    if (p.t < attack_start_s) out.push_back(&p);
  return out;
}

Verdict EventLog::evaluate(double threshold) const {
  Verdict v;
  v.criterion_threshold = threshold;

  const double window_end = attack_end_s > attack_start_s ? attack_end_s : run_end_s;

  // ---- capacity bracket -------------------------------------------------
  // Only ever reported from a staircase run, where the resolution is the step
  // size. In a plain run the connection count ramps to its target in the first
  // second or two, so any number derived from probe timing would be an artifact
  // of ramp speed rather than a measurement of the server.
  if (!capacity.empty()) {
    v.threshold_step = capacity.size() > 1
                           ? capacity[1].connections - capacity[0].connections
                           : capacity[0].connections;
    int last_held = 0;
    bool found = false;
    const CapacityLevel* stopped_short = nullptr;
    for (const auto& lvl : capacity) {
      // A level that never reached its target brackets nothing. Treating it as
      // held would put its number in threshold_lo -- a floor under a load the
      // server was never actually given.
      if (lvl.inconclusive) {
        stopped_short = &lvl;
        break;
      }
      if (lvl.denied) {
        v.threshold_measured = true;
        v.threshold_lo = last_held;
        v.threshold_hi = lvl.connections;
        found = true;
        break;
      }
      last_held = lvl.connections;
    }
    if (found) {
      // nothing more to say; the bracket is the measurement
    } else if (stopped_short) {
      // Deliberately silent on whose fault it was. A level can fail to fill
      // because of a local descriptor or port limit, or because the target
      // refused or throttled the connections -- and from here those look the
      // same. Naming a culprit would send the operator to the wrong machine,
      // which is the one thing this report must never do.
      v.threshold_note =
          "not measured: the search stopped at " +
          std::to_string(stopped_short->connections) +
          " connections, where no more than " +
          std::to_string(stopped_short->reached_max) +
          " could be established at once. ";
      v.threshold_note +=
          last_held > 0
              ? "Service held up to " + std::to_string(last_held) +
                    " connections; the ceiling is somewhere above that and this "
                    "run did not reach it."
              : "No level was ever populated, so this run measured nothing "
                "about the target's ceiling.";
      v.threshold_note +=
          " Check for a local descriptor or ephemeral-port limit before"
          " concluding anything about the target.";
    } else {
      v.threshold_note = "service held at every level up to " +
                         std::to_string(last_held) +
                         " connections; the threshold is above the range tested";
    }
  } else {
    const double per_sample =
        meta.rate * (static_cast<double>(meta.probe_interval_ms) / 1000.0);
    v.threshold_note =
        "not measured: the connection ramp reaches its target faster than the "
        "probe samples it (" +
        fmt("%.0f", per_sample) +
        " connections per sample), so any threshold read off this run would be "
        "an artifact of ramp timing. Use --capacity for a staircase search.";
  }

  // ---- what happened inside the attack window ----------------------------
  // Samples are NOT evenly spaced. A probe that times out occupies the full -p
  // before it can be recorded, while a served one returns in milliseconds, so a
  // run spends far more wall-clock per denied sample than per served one.
  // Counting samples would therefore report a target as more available than it
  // was, by exactly the ratio of timeout to latency. Every duration below is
  // instead computed from the span each sample actually stands for.
  const double nominal_s = static_cast<double>(meta.probe_interval_ms) / 1000.0;
  std::vector<long> served_ms;
  double served_s = 0, degraded_s = 0;

  // What the target actually said, among the probes it answered. A 503 counts
  // as served on purpose -- the server answered, and calling that a denial
  // would conflate it with silence -- but the summary must not then describe a
  // run of nothing but 503s as answering "normally". Tallied over the attack
  // window only, so a healthy baseline does not dilute it.
  int answered_in_window = 0;
  int non_2xx_in_window = 0;
  std::vector<std::pair<int, int>> status_tally;  // code -> count, answered only

  for (std::size_t i = 0; i < probes.size(); ++i) {
    const ProbeSample& p = probes[i];
    if (p.t < attack_start_s || p.t > window_end) continue;
    ++v.probes_total;

    // This sample speaks for the time until the next one starts; the last one
    // speaks for one nominal interval. Both are clipped to the window.
    const double next =
        (i + 1 < probes.size()) ? probes[i + 1].t : p.t + nominal_s;
    double span = std::min(next, window_end) - p.t;
    if (span < 0) span = 0;

    if (p.status_fails) ++v.probes_failing_status;

    if (p.state != Availability::Denied && p.status > 0) {
      ++answered_in_window;
      if (p.status < 200 || p.status > 299) ++non_2xx_in_window;
      bool seen = false;
      for (auto& c : status_tally)
        if (c.first == p.status) { ++c.second; seen = true; break; }
      if (!seen) status_tally.push_back({p.status, 1});
    }

    switch (p.state) {
      case Availability::Ok:
        ++v.probes_served;
        served_ms.push_back(p.ms);
        served_s += span;
        break;
      case Availability::Degraded:
        ++v.probes_degraded;
        degraded_s += span;
        break;
      case Availability::Denied:
        ++v.probes_denied;
        v.unavailable_s += span;
        break;
    }
  }
  v.median_served_ms = median_of(served_ms);

  // Denominator is the time actually observed, not the nominal window: sampling
  // may not have covered every second of it, and pretending otherwise would
  // inflate or deflate the percentage depending on where the gaps fell.
  const double measured_s = served_s + degraded_s + v.unavailable_s;
  if (measured_s > 0) {
    v.availability = served_s / measured_s;
    v.unavailable_pct = 100.0 * v.unavailable_s / measured_s;
  }
  // Two independent ways to fail the gate: not enough of the run was served, or
  // the operator declared certain status codes unacceptable and some came back.
  v.criterion_pass = v.probes_total >= kMinProbesForVerdict &&
                     v.availability >= threshold &&
                     v.probes_failing_status == 0;

  for (const auto& p : probes) {
    if (p.t < attack_start_s || p.t > window_end) continue;
    if (p.state == Availability::Denied) {
      v.time_to_denial_s = p.t - attack_start_s;
      break;
    }
  }

  // Recovery: the first probe answered normally after the attack stopped. Only
  // meaningful if the service had actually stopped answering.
  if (v.probes_denied > 0 && attack_end_s > attack_start_s) {
    for (const auto& p : probes) {
      if (p.t <= attack_end_s) continue;
      if (p.state == Availability::Ok) {
        v.recovery_s = p.t - attack_end_s;
        break;
      }
    }
  }

  // ---- outcome ----------------------------------------------------------
  const auto base = baseline_probes();
  bool baseline_unhealthy = false;
  for (const auto* p : base)
    if (p->state != Availability::Ok) baseline_unhealthy = true;

  // "normally" is a claim about the responses, not just their arrival, and a
  // run answered entirely with 503s has not earned it. Names the code when the
  // target spoke with one voice, counts them when it did not, and says nothing
  // extra when everything was 2xx.
  auto status_phrase = [&]() -> std::string {
    if (answered_in_window == 0 || non_2xx_in_window == 0)
      return " normally throughout the test";
    if (status_tally.size() == 1)
      return " throughout the test, every one with status " +
             std::to_string(status_tally[0].first);
    std::string worst;
    int worst_n = 0;
    for (const auto& c : status_tally)
      if ((c.first < 200 || c.first > 299) && c.second > worst_n) {
        worst_n = c.second;
        worst = std::to_string(c.first);
      }
    // "9 of them" when it was all nine reads as though some were fine.
    if (non_2xx_in_window == answered_in_window)
      return " throughout the test, every one with a non-2xx status (most often "
             + worst + ")";
    return " throughout the test, " + std::to_string(non_2xx_in_window) +
           " of them with a non-2xx status (most often " + worst + ")";
  };

  if (v.probes_total < kMinProbesForVerdict) {
    v.outcome = Outcome::Inconclusive;
    v.summary =
        "Too few probes completed inside the attack window (" +
        std::to_string(v.probes_total) + ") to support a conclusion. Nothing "
        "here should be read as evidence that the target held up.";
  } else if (baseline_unhealthy) {
    v.outcome = Outcome::Inconclusive;
    v.summary =
        "The target was already failing or slow before any load was applied, so "
        "whatever happened during the test cannot be attributed to the test. "
        "Fix or re-check the baseline and run again.";
  } else if (v.probes_denied > 0) {
    v.outcome = Outcome::Denied;
    v.summary =
        "The target stopped answering probe requests " +
        fmt("%.0f", v.time_to_denial_s) + " s after the test began and was "
        "unavailable for " + fmt("%.0f", v.unavailable_s) + " s — " +
        fmt("%.0f", v.unavailable_pct) + "% of the attack window.";
    if (v.recovery_s >= 0) {
      // Recovery can only be observed as fast as the probe grid samples it, so
      // it is stated as a bound rather than as a measurement.
      v.summary += " It answered again within " +
                   fmt("%.0f", std::max(v.recovery_s, nominal_s)) +
                   " s of the test stopping, which is consistent with resource "
                   "exhaustion during the attack rather than a crash.";
    } else if (attack_end_s > attack_start_s) {
      v.summary +=
          " It had not answered again by the time observation ended, so recovery "
          "was not observed.";
    }
  } else if (v.probes_degraded >
             kDegradedShare * static_cast<double>(v.probes_total)) {
    v.outcome = Outcome::Degraded;
    v.summary =
        "The target kept answering every probe, but " +
        std::to_string(v.probes_degraded) + " of " +
        std::to_string(v.probes_total) + " responses took longer than " +
        std::to_string(meta.degraded_above_ms) +
        " ms. Service was slowed, not denied." +
        (non_2xx_in_window > 0
             ? " " + std::to_string(non_2xx_in_window) + " of the answers"
               " carried a non-2xx status."
             : "");
  } else {
    v.outcome = Outcome::Held;
    v.summary =
        "The target answered " + std::to_string(v.probes_served) + " of " +
        std::to_string(v.probes_total) + " probes" + status_phrase() +
        ". Under these conditions it held.";
  }

  {
    // A capacity run never holds -c connections: it climbs a staircase and
    // stops. Reporting -c here said "at 50 connections" for a run whose levels
    // were 2, 4 and 6 -- while the denial-threshold line in the same report
    // correctly said "up to 6". A report that contradicts itself invites the
    // reader to believe whichever half suits them, and the wrong half here
    // overstates the test by an order of magnitude.
    char buf[256];
    if (!capacity.empty()) {
      int highest = 0;
      for (const auto& lvl : capacity)
        if (lvl.connections > highest) highest = lvl.connections;
      std::snprintf(buf, sizeof(buf),
                    "under %s, capacity search up to %d connections",
                    meta.mode_label.c_str(), highest);
    } else {
      std::snprintf(buf, sizeof(buf), "under %s at %d connections",
                    meta.mode_label.c_str(), meta.connections);
    }
    v.scope = buf;
    // On an HTTP/2 run the outcome and the oracle are on different protocols,
    // and the outcome is what gets quoted. "SERVICE DENIED under HTTP/2 rapid
    // reset" reads as a denial of the h2 service; what was actually observed is
    // that an HTTP/1.1 client stopped being served while an h2 attack ran. That
    // is strong evidence of impact and weak evidence about h2 specifically, so
    // the qualifier travels with the headline rather than sitting in the caveat
    // list underneath it.
    if (meta.attack_http2)
      v.scope += ", availability measured over " + meta.probe_protocol;
  }

  // ---- what this run cannot rule out -------------------------------------
  // Stated for every outcome, including the negative ones: "held" is just as
  // conditional as "denied", and a reader who takes it as a clean bill of health
  // has been misled by omission.
  v.caveats.push_back(
      "Packet loss or congestion between this host and the target could produce "
      "the same probe timings as server-side exhaustion.");
  v.caveats.push_back(
      "Rate limiting, a WAF, or an upstream shedding this client specifically "
      "would look identical from here.");
  v.caveats.push_back(
      "An intermediary (load balancer, CDN, reverse proxy) may have failed or "
      "held up rather than the origin.");
  v.caveats.push_back("Single run — re-run to confirm.");
  if (!meta.probe_proxy.empty()) {
    v.caveats.push_back(
        "Probes went through " + meta.probe_proxy +
        "; the proxy's own health is part of every measurement here.");
  }
  // The availability oracle and the attack can be on different protocols, and
  // on an HTTP/2 run they always are. A server can hold up perfectly well on
  // HTTP/1.1 while its h2 path is exhausted -- separate connection pools,
  // separate stream limits, often a different backend entirely -- so "held"
  // here is weaker than it looks, and "denied" implicates something both paths
  // share. Either way the reader has to know which door was knocked on.
  // Slow read works by advertising a window too small for the response, so a
  // kernel that overrides it changes the attack rather than merely the log line.
  // The run is still valid -- the window does eventually close -- but it closed
  // around a far bigger buffer than the operator asked for, and a reader
  // comparing runs across platforms needs to know that.
  if (meta.window_overridden && meta.window_requested > 0) {
    v.caveats.push_back(
        "The kernel granted a " + std::to_string(meta.kernel_rcvbuf) +
        " B receive buffer against the " + std::to_string(meta.window_requested) +
        " B requested by -w/-y, so the advertised window was not under this "
        "tool's control. Each connection absorbed more of the response than "
        "intended before backing up.");
  }
  if (meta.attack_http2) {
    v.caveats.push_back(
        "Availability was measured with " + meta.probe_protocol +
        " requests, not over the HTTP/2 path the attack used. A target can "
        "serve HTTP/1.1 normally while its HTTP/2 side is exhausted, and the "
        "reverse is also possible.");
  }
  if (v.outcome == Outcome::Held) {
    v.caveats.push_back(
        "Holding at " + std::to_string(meta.connections) +
        " connections says nothing about behaviour above that number.");
  }
  if (base.empty()) {
    v.caveats.push_back(
        "No pre-attack baseline was captured, so the target's healthy response "
        "time is unknown.");
  }
  return v;
}

}  // namespace slowhttp
