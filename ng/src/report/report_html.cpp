// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Self-contained HTML report. Everything -- CSS, SVG, the run data, the drawing
// code -- is inlined, so the file opens offline, inside a container, and on an
// air-gapped network. The original tool's report loads Google Chart Tools over
// the network and renders nothing in exactly those situations.
#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <string>
#include <vector>

#include "slowhttp/report.hpp"

namespace slowhttp {
namespace {

std::string esc(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      default:  out += c;
    }
  }
  return out;
}

std::string num(double v, int decimals = 0) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%.*f", decimals, v);
  return buf;
}

// Thin spaces between thousands: "2 980 ms" is legible at a glance in a way that
// "2980 ms" is not, and it matches the design preview. Built left to right, since
// the separator is multi-byte UTF-8 and cannot survive a reversed build.
std::string group(long v) {
  const std::string s = std::to_string(v);
  if (s.size() <= 4) return s;
  static const char kThinSpace[] = "\xE2\x80\x89";  // U+2009
  const std::size_t lead = s.size() % 3 == 0 ? 3 : s.size() % 3;
  std::string out = s.substr(0, lead);
  for (std::size_t i = lead; i < s.size(); i += 3) {
    out += kThinSpace;
    out += s.substr(i, 3);
  }
  return out;
}

struct OutcomeStyle {
  const char* cls;    // suffix for v-* classes
  const char* pill;   // pill class
  const char* word;
  const char* icon;   // inline SVG path set
};

OutcomeStyle style_for(Outcome o) {
  static const char* kWarn =
      "<path d=\"M12 2.6 22.4 20.6H1.6Z\" fill=\"none\" stroke=\"currentColor\""
      " stroke-width=\"2\" stroke-linejoin=\"round\"/>"
      "<path d=\"M12 9.4v5.2\" stroke=\"currentColor\" stroke-width=\"2.2\""
      " stroke-linecap=\"round\"/>"
      "<circle cx=\"12\" cy=\"17.6\" r=\"1.3\" fill=\"currentColor\"/>";
  static const char* kCheck =
      "<circle cx=\"12\" cy=\"12\" r=\"10\" fill=\"none\" stroke=\"currentColor\""
      " stroke-width=\"2\"/>"
      "<path d=\"M7.2 12.4l3.2 3.2 6.4-6.8\" fill=\"none\" stroke=\"currentColor\""
      " stroke-width=\"2.2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>";
  static const char* kQuestion =
      "<circle cx=\"12\" cy=\"12\" r=\"10\" fill=\"none\" stroke=\"currentColor\""
      " stroke-width=\"2\"/>"
      "<path d=\"M9.2 9.3a2.9 2.9 0 1 1 3.6 2.9v1.9\" fill=\"none\""
      " stroke=\"currentColor\" stroke-width=\"2.1\" stroke-linecap=\"round\"/>"
      "<circle cx=\"12.4\" cy=\"17.4\" r=\"1.3\" fill=\"currentColor\"/>";

  switch (o) {
    case Outcome::Denied:   return {"den", "den", "SERVICE DENIED", kWarn};
    case Outcome::Degraded: return {"deg", "deg", "SERVICE DEGRADED", kWarn};
    case Outcome::Held:     return {"ok", "ok", "SERVICE HELD", kCheck};
    case Outcome::Inconclusive:
    default:                return {"unk", "unk", "INCONCLUSIVE", kQuestion};
  }
}

const char* pill_for(Availability a) {
  switch (a) {
    case Availability::Ok:       return "ok";
    case Availability::Degraded: return "deg";
    case Availability::Denied:   return "den";
  }
  return "unk";
}

// ---- the stylesheet, carried over from docs/report-preview.html -------------
const char* kStyle = R"CSS(
:root {
  --ground:#f6f7f9; --surface:#ffffff; --surface-2:#fbfcfd;
  --ink:#111820; --ink-2:#5a6673; --ink-3:#8a95a1;
  --rule:#dfe4ea; --rule-2:#eef1f5; --accent:#0b7a85;
  --ok:#0ca30c; --degraded:#fab219; --denied:#d03b3b; --unknown:#8a95a1;
  --ok-ink:#0a7a0a; --degraded-ink:#8a5d00; --denied-ink:#b52d2d; --unknown-ink:#5a6673;
  --ok-bg:#e8f5ee; --degraded-bg:#fbf1dc; --denied-bg:#f9e7e4; --unknown-bg:#eef1f5;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground:#0c1014; --surface:#131a21; --surface-2:#0f161c;
    --ink:#e6ecf2; --ink-2:#9aa7b4; --ink-3:#6b7885;
    --rule:#232d37; --rule-2:#1b232b; --accent:#3fd0de;
    /* status marks deliberately NOT overridden: a state keeps the same colour in
       both themes so it never has to be relearned */
    --ok-ink:#35c435; --degraded-ink:#fab219; --denied-ink:#f06a6a; --unknown-ink:#9aa7b4;
    --ok-bg:#14261e; --degraded-bg:#2a2313; --denied-bg:#2b1714; --unknown-bg:#1b232b;
  }
}
:root[data-theme="dark"] {
  --ground:#0c1014; --surface:#131a21; --surface-2:#0f161c;
  --ink:#e6ecf2; --ink-2:#9aa7b4; --ink-3:#6b7885;
  --rule:#232d37; --rule-2:#1b232b; --accent:#3fd0de;
  --ok-ink:#35c435; --degraded-ink:#fab219; --denied-ink:#f06a6a; --unknown-ink:#9aa7b4;
  --ok-bg:#14261e; --degraded-bg:#2a2313; --denied-bg:#2b1714; --unknown-bg:#1b232b;
}
:root[data-theme="light"] {
  --ground:#f6f7f9; --surface:#ffffff; --surface-2:#fbfcfd;
  --ink:#111820; --ink-2:#5a6673; --ink-3:#8a95a1;
  --rule:#dfe4ea; --rule-2:#eef1f5; --accent:#0b7a85;
  --ok-ink:#0a7a0a; --degraded-ink:#8a5d00; --denied-ink:#b52d2d; --unknown-ink:#5a6673;
  --ok-bg:#e8f5ee; --degraded-bg:#fbf1dc; --denied-bg:#f9e7e4; --unknown-bg:#eef1f5;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--ground); color:var(--ink); font-family:var(--sans);
       line-height:1.55; -webkit-font-smoothing:antialiased; }
.wrap { max-width:1120px; margin:0 auto; padding:32px 24px 64px;
        display:flex; flex-direction:column; gap:28px; }
.masthead { display:flex; flex-wrap:wrap; align-items:baseline; justify-content:space-between;
            gap:12px 24px; padding-bottom:16px; border-bottom:2px solid var(--ink); }
.tool { font-family:var(--mono); font-size:13px; font-weight:700; letter-spacing:0.08em;
        text-transform:uppercase; color:var(--accent); }
.tool span { color:var(--ink-3); font-weight:400; }
.runstamp { font-family:var(--mono); font-size:12px; color:var(--ink-3);
            font-variant-numeric:tabular-nums; }
h1 { font-family:var(--mono); font-size:26px; font-weight:700; letter-spacing:-0.01em;
     margin:0; flex-basis:100%; text-wrap:balance; }
.verdict { display:grid; grid-template-columns:6px 1fr; background:var(--surface);
           border:1px solid var(--rule); border-radius:3px; overflow:hidden; }
.verdict-stripe.v-ok  { background:var(--ok); }
.verdict-stripe.v-deg { background:var(--degraded); }
.verdict-stripe.v-den { background:var(--denied); }
.verdict-stripe.v-unk { background:var(--unknown); }
.verdict-body { padding:20px 22px; display:flex; flex-direction:column; gap:8px; }
.verdict-line { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.verdict-word { font-family:var(--mono); font-size:29px; font-weight:700;
                letter-spacing:-0.02em; line-height:1.05; }
.verdict-word.v-ok  { color:var(--ok-ink); }
.verdict-word.v-deg { color:var(--degraded-ink); }
.verdict-word.v-den { color:var(--denied-ink); }
.verdict-word.v-unk { color:var(--unknown-ink); }
.verdict-icon { flex:none; }
.verdict-icon.v-ok  { color:var(--ok); }
.verdict-icon.v-deg { color:var(--degraded); }
.verdict-icon.v-den { color:var(--denied); }
.verdict-icon.v-unk { color:var(--unknown); }
.verdict-sub { font-family:var(--mono); font-size:12px; letter-spacing:0.06em;
               text-transform:uppercase; color:var(--ink-3); }
.verdict p { margin:0; color:var(--ink-2); max-width:68ch; font-size:15px; }
.verdict b { color:var(--ink); font-weight:600; }
.caveat { margin:0; font-size:13.5px !important; color:var(--ink-3) !important;
          border-left:2px solid var(--rule); padding-left:12px; max-width:68ch; }
.caveat b { color:var(--ink-2) !important; }
.caveat ul { margin:6px 0 0; padding-left:18px; }
.caveat li { margin:2px 0; }
.stats { display:grid; grid-template-columns:repeat(auto-fit, minmax(190px,1fr)); gap:1px;
         background:var(--rule); border:1px solid var(--rule); border-radius:3px; overflow:hidden; }
.tile { background:var(--surface); padding:16px 18px; display:flex; flex-direction:column; gap:6px; }
.tile-label { font-family:var(--mono); font-size:10.5px; letter-spacing:0.09em;
              text-transform:uppercase; color:var(--ink-3); }
.tile-value { font-family:var(--mono); font-size:27px; font-weight:700; line-height:1.05;
              font-variant-numeric:tabular-nums; letter-spacing:-0.02em; }
.tile-value.crit { color:var(--denied-ink); }
.tile-value.warn { color:var(--degraded-ink); }
.tile-value.good { color:var(--ok-ink); }
.tile-value.muted { color:var(--ink-3); font-size:18px; font-weight:400; padding-top:6px; }
.tile-note { font-family:var(--mono); font-size:11.5px; color:var(--ink-3);
             font-variant-numeric:tabular-nums; }
.card { background:var(--surface); border:1px solid var(--rule); border-radius:3px;
        padding:20px 22px 16px; }
.card-head { display:flex; align-items:baseline; justify-content:space-between; gap:16px;
             flex-wrap:wrap; margin-bottom:4px; }
h2 { font-family:var(--mono); font-size:12px; font-weight:700; letter-spacing:0.1em;
     text-transform:uppercase; margin:0; color:var(--ink); }
.card-note { font-size:13px; color:var(--ink-3); max-width:60ch; }
.chart-scroll { overflow-x:auto; }
svg.chart { display:block; width:100%; min-width:640px; height:auto; }
.panel-label { font-family:var(--mono); font-size:11px; fill:var(--ink-2);
               letter-spacing:0.06em; text-transform:uppercase; }
.axis-text { font-family:var(--mono); font-size:10.5px; fill:var(--ink-3); }
.gridline { stroke:var(--rule-2); stroke-width:1; }
.axisline { stroke:var(--rule); stroke-width:1; }
.marker-line { stroke:var(--ink-3); stroke-width:1; stroke-dasharray:2 3; }
.marker-dot { fill:var(--surface); stroke:var(--ink-2); stroke-width:1.5; }
.marker-num { font-family:var(--mono); font-size:10px; font-weight:700; fill:var(--ink);
              text-anchor:middle; }
.seg-ok { fill:var(--ok); } .seg-degraded { fill:var(--degraded); }
.seg-denied { fill:var(--denied); }
.seg-sep { stroke:var(--surface); stroke-width:2; }
.hatch-stroke { stroke:var(--surface); stroke-width:1.4; }
.conn-area { fill:var(--accent); opacity:0.16; }
.conn-line { stroke:var(--accent); stroke-width:2; fill:none; stroke-linejoin:round; }
.lat-line { stroke:var(--ink-2); stroke-width:2; fill:none; stroke-linejoin:round; }
.lat-dot { fill:var(--ink-2); stroke:var(--surface); stroke-width:2; }
.lat-dot.warn { fill:var(--degraded); }
.deadzone { fill:var(--denied); opacity:0.07; }
.deadzone-label { font-family:var(--mono); font-size:11px; fill:var(--denied-ink);
                  letter-spacing:0.08em; text-transform:uppercase; }
.crosshair { stroke:var(--ink); stroke-width:1; opacity:0.45; pointer-events:none; }
.legend { display:flex; flex-wrap:wrap; gap:8px 20px; margin-top:14px; padding-top:12px;
          border-top:1px solid var(--rule-2); }
.legend-item { display:flex; align-items:center; gap:7px; font-family:var(--mono);
               font-size:11.5px; color:var(--ink-2); }
.swatch { width:22px; height:11px; border-radius:1px; flex:none; }
.markers { display:flex; flex-wrap:wrap; gap:6px 18px; margin-top:10px; }
.mk { display:flex; align-items:center; gap:7px; font-family:var(--mono); font-size:11.5px;
      color:var(--ink-2); font-variant-numeric:tabular-nums; }
.mk-n { width:16px; height:16px; border-radius:50%; flex:none; border:1.5px solid var(--ink-2);
        color:var(--ink); font-size:10px; font-weight:700; display:grid; place-items:center; }
.mk time { color:var(--ink-3); }
.table-scroll { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-family:var(--mono); font-size:12.5px;
        min-width:520px; }
caption { text-align:left; font-size:13px; color:var(--ink-3); padding-bottom:10px;
          font-family:var(--sans); }
th, td { text-align:left; padding:7px 14px 7px 0; border-bottom:1px solid var(--rule-2);
         font-variant-numeric:tabular-nums; vertical-align:top; }
th { color:var(--ink-3); font-weight:400; font-size:10.5px; letter-spacing:0.09em;
     text-transform:uppercase; border-bottom-color:var(--rule); }
td.t { color:var(--ink-3); white-space:nowrap; }
tr:last-child td { border-bottom:none; }
.pill { display:inline-block; padding:1px 7px; border-radius:2px; font-size:10.5px;
        letter-spacing:0.06em; text-transform:uppercase; }
.pill.ok { background:var(--ok-bg); color:var(--ok-ink); }
.pill.deg { background:var(--degraded-bg); color:var(--degraded-ink); }
.pill.den { background:var(--denied-bg); color:var(--denied-ink); }
.pill.unk { background:var(--unknown-bg); color:var(--unknown-ink); }
.bracket { display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; padding:14px 16px;
           margin:4px 0 18px; background:var(--surface-2); border:1px solid var(--rule);
           border-radius:3px; }
.bracket-label { font-family:var(--mono); font-size:10.5px; letter-spacing:0.09em;
                 text-transform:uppercase; color:var(--ink-3); }
.bracket-value { font-family:var(--mono); font-size:24px; font-weight:700;
                 font-variant-numeric:tabular-nums; letter-spacing:-0.01em; }
.bracket-value.muted { font-size:15px; font-weight:400; color:var(--ink-3); }
.bracket-note { font-family:var(--mono); font-size:11.5px; color:var(--ink-3); }
.params { display:grid; grid-template-columns:repeat(auto-fit, minmax(210px,1fr));
          gap:14px 28px; margin:0; }
.param { display:flex; flex-direction:column; gap:2px; }
.param dt { font-family:var(--mono); font-size:10.5px; letter-spacing:0.09em;
            text-transform:uppercase; color:var(--ink-3); }
.param dd { margin:0; font-family:var(--mono); font-size:13.5px;
            font-variant-numeric:tabular-nums; word-break:break-all; }
footer { border-top:1px solid var(--rule); padding-top:16px; font-size:12.5px;
         color:var(--ink-3); display:flex; flex-direction:column; gap:6px; }
footer code { font-family:var(--mono); color:var(--ink-2); }
#tip { position:fixed; pointer-events:none; z-index:10; background:var(--surface);
       border:1px solid var(--rule); border-radius:3px; padding:8px 10px;
       font-family:var(--mono); font-size:11.5px; line-height:1.5; color:var(--ink);
       box-shadow:0 4px 14px rgba(0,0,0,0.14); font-variant-numeric:tabular-nums;
       opacity:0; transition:opacity 0.1s; white-space:nowrap; }
#tip.on { opacity:1; }
#tip .r { display:flex; gap:10px; justify-content:space-between; }
#tip .k { color:var(--ink-3); }
a:focus-visible, [tabindex]:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
@media (prefers-reduced-motion: reduce) { * { transition:none !important; } }
)CSS";

// ---- the chart, drawn from the embedded RUN object --------------------------
const char* kScript = R"JS(
(function () {
  "use strict";
  var R = window.RUN;
  var probes = R.probes || [], conns = R.conns || [];
  var T_END = Math.max(R.run_end || 0, 1);

  var svg = document.getElementById("chart");
  if (!probes.length) {
    document.getElementById("chart-wrap").innerHTML =
      '<p class="card-note">No availability samples were collected, so there is ' +
      'nothing to plot.</p>';
    return;
  }

  var X0 = 66, X1 = 1064, W = X1 - X0;
  var RIB_Y = 34, RIB_H = 34;
  var CON_Y = 116, CON_H = 116, CON_B = CON_Y + CON_H;
  var LAT_Y = 280, LAT_H = 104, LAT_B = LAT_Y + LAT_H;
  var AXIS_Y = LAT_B;

  function x(t) { return X0 + (t / T_END) * W; }

  var connMax = 1;
  conns.forEach(function (d) { if (d.n > connMax) connMax = d.n; });
  var connTop = Math.max(1, Math.ceil(connMax * 1.1));
  function yC(n) { return CON_B - (n / connTop) * CON_H; }

  var lats = probes.filter(function (p) { return p.ms != null; })
                   .map(function (p) { return p.ms; });
  var loMs = lats.length ? Math.max(1, Math.min.apply(null, lats)) : 1;
  var hiMs = lats.length ? Math.max.apply(null, lats) : 1000;
  if (hiMs < loMs * 4) hiMs = loMs * 4;
  var L0 = Math.log10(loMs), L1 = Math.log10(hiMs);
  function yL(ms) {
    if (L1 === L0) return LAT_B - LAT_H / 2;
    return LAT_B - ((Math.log10(Math.max(ms, 1)) - L0) / (L1 - L0)) * LAT_H;
  }

  var NS = "http://www.w3.org/2000/svg";
  function el(n, a) {
    var e = document.createElementNS(NS, n);
    for (var k in a) e.setAttribute(k, a[k]);
    return e;
  }
  var g = document.getElementById("plot");
  function add(e) { g.appendChild(e); return e; }
  function text(s, X, Y, cls, anchor) {
    var e = el("text", { x: X, y: Y, "class": cls });
    if (anchor) e.setAttribute("text-anchor", anchor);
    e.textContent = s;
    return add(e);
  }

  // panel 1: availability ribbon. Merges consecutive same-state samples so the
  // eye reads runs, not individual probes.
  text("service availability", X0, RIB_Y - 10, "panel-label");
  var stateClass = { served: "seg-ok", degraded: "seg-degraded", denied: "seg-denied" };
  var stateFill = { served: null, degraded: "url(#hatch-deg)", denied: "url(#hatch-den)" };
  var runStart = 0;
  for (var i = 0; i <= probes.length; i++) {
    var cur = probes[i], prev = probes[i - 1];
    if (i > 0 && (!cur || cur.state !== prev.state)) {
      var xs = x(probes[runStart].t);
      var xe = cur ? x(cur.t) : x(T_END);
      add(el("rect", { x: xs, y: RIB_Y, width: Math.max(1, xe - xs), height: RIB_H,
                       "class": stateClass[prev.state] || "seg-ok" }));
      if (stateFill[prev.state]) {
        add(el("rect", { x: xs, y: RIB_Y, width: Math.max(1, xe - xs), height: RIB_H,
                         fill: stateFill[prev.state] }));
      }
      if (cur) add(el("line", { x1: xe, y1: RIB_Y, x2: xe, y2: RIB_Y + RIB_H,
                                "class": "seg-sep" }));
      runStart = i;
    }
  }

  // panel 2: connections actually held (not the -c that was asked for)
  text("connections held", X0, CON_Y - 10, "panel-label");
  [0, Math.round(connTop / 2), connTop].forEach(function (n) {
    add(el("line", { x1: X0, y1: yC(n), x2: X1, y2: yC(n), "class": "gridline" }));
    text(String(n), X0 - 10, yC(n) + 3.5, "axis-text", "end");
  });
  if (conns.length) {
    var cPts = conns.map(function (d) {
      return x(d.t).toFixed(1) + "," + yC(d.n).toFixed(1);
    }).join(" ");
    add(el("polygon", { points: X0 + "," + CON_B + " " + cPts + " " + X1 + "," + CON_B,
                        "class": "conn-area" }));
    add(el("polyline", { points: cPts, "class": "conn-line" }));
  }

  // panel 3: probe latency on a log scale, so 12 ms and 2 980 ms share an axis
  text("probe response time", X0, LAT_Y - 10, "panel-label");
  var ticks = [];
  for (var e10 = Math.floor(L0); e10 <= Math.ceil(L1); e10++) {
    var v = Math.pow(10, e10);
    if (v >= loMs * 0.9 && v <= hiMs * 1.1) ticks.push(v);
  }
  if (ticks.length < 2) ticks = [loMs, hiMs];
  ticks.forEach(function (ms) {
    add(el("line", { x1: X0, y1: yL(ms), x2: X1, y2: yL(ms), "class": "gridline" }));
    text(Math.round(ms) + " ms", X0 - 10, yL(ms) + 3.5, "axis-text", "end");
  });

  // stretches with no response at all: shaded, hatched and labelled, because an
  // empty gap in a line chart reads as "no data" rather than "no service"
  var zi = 0;
  while (zi < probes.length) {
    if (probes[zi].state !== "denied") { zi++; continue; }
    var zs = zi;
    while (zi < probes.length && probes[zi].state === "denied") zi++;
    var d0 = x(probes[zs].t);
    var d1 = zi < probes.length ? x(probes[zi].t) : x(T_END);
    if (d1 - d0 < 2) d1 = d0 + 2;
    add(el("rect", { x: d0, y: LAT_Y, width: d1 - d0, height: LAT_H, "class": "deadzone" }));
    add(el("rect", { x: d0, y: LAT_Y, width: d1 - d0, height: LAT_H,
                     fill: "url(#hatch-den)", opacity: "0.28" }));
    if (d1 - d0 > 190) {
      text("no response · timeout " + R.timeout_ms + " ms", (d0 + d1) / 2,
           LAT_Y + LAT_H / 2 + 4, "deadzone-label", "middle");
    }
  }

  // latency line, split around gaps so it never draws through a dead zone
  var seg = [];
  function flush() {
    if (seg.length > 1) add(el("polyline", { points: seg.join(" "), "class": "lat-line" }));
    seg = [];
  }
  probes.forEach(function (p) {
    if (p.ms == null) { flush(); return; }
    seg.push(x(p.t).toFixed(1) + "," + yL(p.ms).toFixed(1));
  });
  flush();
  probes.forEach(function (p) {
    if (p.ms == null) return;
    add(el("circle", { cx: x(p.t), cy: yL(p.ms), r: 3.6,
                       "class": "lat-dot" + (p.state === "degraded" ? " warn" : "") }));
  });

  // shared x axis
  add(el("line", { x1: X0, y1: AXIS_Y, x2: X1, y2: AXIS_Y, "class": "axisline" }));
  var stepChoices = [1, 2, 5, 10, 20, 30, 60, 120, 300, 600];
  var step = stepChoices[stepChoices.length - 1];
  for (var si = 0; si < stepChoices.length; si++) {
    if (T_END / stepChoices[si] <= 8) { step = stepChoices[si]; break; }
  }
  for (var t = 0; t <= T_END + 0.001; t += step) {
    add(el("line", { x1: x(t), y1: AXIS_Y, x2: x(t), y2: AXIS_Y + 5, "class": "axisline" }));
    text(Math.round(t) + " s", x(t), AXIS_Y + 18, "axis-text", "middle");
  }

  // numbered event markers: the order is the story
  (R.markers || []).forEach(function (m, idx) {
    add(el("line", { x1: x(m.t), y1: RIB_Y, x2: x(m.t), y2: AXIS_Y, "class": "marker-line" }));
    add(el("circle", { cx: x(m.t), cy: 14, r: 8.5, "class": "marker-dot" }));
    text(String(idx + 1), x(m.t), 17.5, "marker-num", "middle");
  });

  // hover: one crosshair reads all three panels at the same instant
  var cross = add(el("line", { x1: 0, y1: RIB_Y, x2: 0, y2: AXIS_Y, "class": "crosshair",
                               visibility: "hidden" }));
  var hit = add(el("rect", { x: X0, y: RIB_Y, width: W, height: AXIS_Y - RIB_Y,
                             fill: "transparent" }));
  var tip = document.getElementById("tip");
  var label = { served: "served", degraded: "degraded", denied: "no response" };

  function nearest(arr, t) {
    return arr.reduce(function (a, b) {
      return Math.abs(b.t - t) < Math.abs(a.t - t) ? b : a;
    });
  }
  function move(ev) {
    var box = svg.getBoundingClientRect();
    var t = ((ev.clientX - box.left) / box.width * 1080 - X0) / W * T_END;
    t = Math.max(0, Math.min(T_END, t));
    cross.setAttribute("visibility", "visible");
    cross.setAttribute("x1", x(t));
    cross.setAttribute("x2", x(t));
    var p = nearest(probes, t);
    var rows =
      '<div class="r"><span class="k">t</span><span>' + t.toFixed(1) + ' s</span></div>' +
      '<div class="r"><span class="k">state</span><span>' + (label[p.state] || p.state) +
      '</span></div>' +
      '<div class="r"><span class="k">probe</span><span>' +
      (p.ms == null ? "timeout" : p.ms + " ms") + '</span></div>';
    if (conns.length) {
      var c = nearest(conns, t);
      rows += '<div class="r"><span class="k">held</span><span>' + c.n + ' conn</span></div>';
    }
    tip.innerHTML = rows;
    tip.classList.add("on");
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    var tx = ev.clientX + 14, ty = ev.clientY - th - 10;
    if (tx + tw > innerWidth - 8) tx = ev.clientX - tw - 14;
    if (ty < 8) ty = ev.clientY + 16;
    tip.style.left = tx + "px";
    tip.style.top = ty + "px";
  }
  function leave() {
    cross.setAttribute("visibility", "hidden");
    tip.classList.remove("on");
  }
  hit.addEventListener("mousemove", move);
  hit.addEventListener("mouseleave", leave);
  hit.addEventListener("touchmove", function (e) { move(e.touches[0]); }, { passive: true });
  hit.addEventListener("touchend", leave);
})();
)JS";

std::string js_string(const std::string& s) {
  std::string out = "\"";
  for (char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '<':  out += "\\u003c"; break;  // can't close the <script> element
      case '/':  out += "\\/"; break;
      default:   out += c;
    }
  }
  return out + "\"";
}

// The run data the chart draws from. Same numbers as the JSON file, taken from
// the same EventLog.
std::string embed_data(const EventLog& log, const Verdict& v) {
  std::string o = "window.RUN = {\n";
  o += "  run_end: " + num(log.run_end_s, 2) + ",\n";
  o += "  attack_start: " + num(log.attack_start_s, 2) + ",\n";
  o += "  attack_end: " + num(log.attack_end_s, 2) + ",\n";
  o += "  timeout_ms: " + std::to_string(log.meta.probe_timeout_ms) + ",\n";

  o += "  probes: [";
  for (std::size_t i = 0; i < log.probes.size(); ++i) {
    const auto& p = log.probes[i];
    o += (i ? "," : "");
    o += "{t:" + num(p.t, 2) + ",state:\"" + availability_name(p.state) +
         "\",ms:" + (p.ms < 0 ? "null" : std::to_string(p.ms)) + "}";
  }
  o += "],\n";

  o += "  conns: [";
  for (std::size_t i = 0; i < log.conns.size(); ++i) {
    o += (i ? "," : "");
    o += "{t:" + num(log.conns[i].t, 2) + ",n:" + std::to_string(log.conns[i].held) + "}";
  }
  o += "],\n";

  o += "  markers: [";
  bool first = true;
  auto marker = [&](double t, const std::string& label) {
    if (!first) o += ",";
    first = false;
    o += "{t:" + num(t, 2) + ",label:" + js_string(label) + "}";
  };
  marker(log.attack_start_s, "attack started");
  if (v.time_to_denial_s >= 0)
    marker(log.attack_start_s + v.time_to_denial_s, "first denial");
  if (log.attack_end_s > log.attack_start_s) marker(log.attack_end_s, "attack stopped");
  if (v.recovery_s >= 0) marker(log.attack_end_s + v.recovery_s, "service restored");
  o += "]\n};\n";
  return o;
}

std::string markers_html(const EventLog& log, const Verdict& v) {
  struct M { double t; const char* label; };
  std::vector<M> ms;
  ms.push_back({log.attack_start_s, "attack started"});
  if (v.time_to_denial_s >= 0)
    ms.push_back({log.attack_start_s + v.time_to_denial_s, "first denial"});
  if (log.attack_end_s > log.attack_start_s)
    ms.push_back({log.attack_end_s, "attack stopped"});
  if (v.recovery_s >= 0)
    ms.push_back({log.attack_end_s + v.recovery_s, "service restored"});

  std::string o;
  for (std::size_t i = 0; i < ms.size(); ++i) {
    o += "      <span class=\"mk\"><span class=\"mk-n\">" + std::to_string(i + 1) +
         "</span> " + ms[i].label + " <time>t=" + num(ms[i].t, 1) + " s</time></span>\n";
  }
  return o;
}

}  // namespace

std::string render_html(const EventLog& log, const Verdict& v) {
  const RunMeta& m = log.meta;
  const OutcomeStyle st = style_for(v.outcome);

  std::string o;
  o.reserve(65536);
  o += "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
  o += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
  o += "<title>slowhttptest-ng — " + esc(m.mode_label) + " against " +
       esc(m.target_url) + "</title>\n";
  o += "<style>";
  o += kStyle;
  o += "</style>\n</head>\n<body>\n<div class=\"wrap\">\n";

  // ---- masthead ----
  o += "  <header class=\"masthead\">\n";
  o += "    <div class=\"tool\">slowhttptest-ng <span>v" + esc(m.tool_version) +
       "</span></div>\n";
  o += "    <div class=\"runstamp\">run " + esc(m.started_utc) + " · " +
       num(log.run_end_s, 0) + " s elapsed</div>\n";
  o += "    <h1>" + esc(m.mode_label) + " against " + esc(m.target_url) + "</h1>\n";
  o += "  </header>\n\n";

  // ---- verdict: an outcome, scoped to the conditions that produced it ----
  o += "  <section class=\"verdict\" aria-labelledby=\"verdict-word\">\n";
  o += std::string("    <div class=\"verdict-stripe v-") + st.cls + "\"></div>\n";
  o += "    <div class=\"verdict-body\">\n";
  o += "      <div class=\"verdict-line\">\n";
  // Icon + word + scope: state is never carried by colour alone.
  o += std::string("        <svg class=\"verdict-icon v-") + st.cls +
       "\" width=\"30\" height=\"30\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">" +
       st.icon + "</svg>\n";
  o += std::string("        <strong class=\"verdict-word v-") + st.cls +
       "\" id=\"verdict-word\">" + st.word + "</strong>\n";
  o += "        <span class=\"verdict-sub\">" + esc(v.scope) + "</span>\n";
  o += "      </div>\n";
  o += "      <p>" + esc(v.summary) + "</p>\n";
  o += "      <div class=\"caveat\"><b>Not ruled out:</b>\n        <ul>\n";
  for (const auto& c : v.caveats) o += "          <li>" + esc(c) + "</li>\n";
  o += "        </ul>\n      </div>\n";
  o += "    </div>\n  </section>\n\n";

  // ---- key measurements ----
  o += "  <section class=\"stats\" aria-label=\"Key measurements\">\n";

  o += "    <div class=\"tile\">\n      <span class=\"tile-label\">Time to denial</span>\n";
  if (v.time_to_denial_s >= 0) {
    o += "      <span class=\"tile-value crit\">" + num(v.time_to_denial_s, 0) +
         " s</span>\n      <span class=\"tile-note\">first probe timeout</span>\n";
  } else {
    o += "      <span class=\"tile-value muted\">never</span>\n"
         "      <span class=\"tile-note\">service answered throughout</span>\n";
  }
  o += "    </div>\n";

  o += "    <div class=\"tile\">\n      <span class=\"tile-label\">Unavailable</span>\n";
  const char* unavail_cls = v.unavailable_s > 0 ? "crit" : "good";
  o += std::string("      <span class=\"tile-value ") + unavail_cls + "\">" +
       num(v.unavailable_s, 0) + " s</span>\n";
  o += "      <span class=\"tile-note\">" + num(v.unavailable_pct, 0) +
       "% of the attack window</span>\n    </div>\n";

  o += "    <div class=\"tile\">\n      <span class=\"tile-label\">Denial threshold</span>\n";
  if (v.threshold_measured) {
    o += "      <span class=\"tile-value crit\">" + std::to_string(v.threshold_lo) +
         " &lt; n &le; " + std::to_string(v.threshold_hi) + "</span>\n";
    o += "      <span class=\"tile-note\">connections · step " +
         std::to_string(v.threshold_step) + "</span>\n";
  } else {
    o += "      <span class=\"tile-value muted\">not measured</span>\n";
    o += "      <span class=\"tile-note\">see capacity section</span>\n";
  }
  o += "    </div>\n";

  o += "    <div class=\"tile\">\n      <span class=\"tile-label\">Recovery</span>\n";
  if (v.recovery_s >= 0) {
    // Recovery is only visible at the resolution the probe grid samples it, so
    // the tile states a bound rather than implying sub-interval precision.
    const double nominal_s = m.probe_interval_ms / 1000.0;
    const bool sub_grid = v.recovery_s < nominal_s;
    o += "      <span class=\"tile-value\">" +
         std::string(sub_grid ? "&le; " : "") +
         num(sub_grid ? nominal_s : v.recovery_s, 0) + " s</span>\n";
    o += std::string("      <span class=\"tile-note\">") +
         (sub_grid ? "within one probe interval" : "after the attack stopped") +
         "</span>\n";
  } else if (v.probes_denied > 0) {
    o += "      <span class=\"tile-value muted\">not observed</span>\n";
    o += "      <span class=\"tile-note\">still down when watching ended</span>\n";
  } else {
    o += "      <span class=\"tile-value muted\">n/a</span>\n";
    o += "      <span class=\"tile-note\">service never went down</span>\n";
  }
  o += "    </div>\n  </section>\n\n";

  // ---- timeline ----
  o += "  <section class=\"card\">\n    <div class=\"card-head\">\n";
  o += "      <h2>Timeline</h2>\n";
  o += "      <p class=\"card-note\">Three measurements on one shared time axis:"
       " whether the service answered, how many connections the tool actually"
       " held, and how long a probe took. Inside the attack window: <b>" +
       std::to_string(v.probes_served) + " served</b>, <b>" +
       std::to_string(v.probes_degraded) + " degraded</b>, <b>" +
       std::to_string(v.probes_denied) + " denied</b> of " +
       std::to_string(v.probes_total) + " probes.</p>\n";
  o += "    </div>\n\n";
  o += "    <div class=\"chart-scroll\" id=\"chart-wrap\">\n";
  o += "      <svg class=\"chart\" id=\"chart\" viewBox=\"0 0 1080 470\" role=\"img\"\n";
  o += "           aria-label=\"" + esc(v.summary) + "\">\n";
  o += "        <defs>\n";
  // Hatch patterns give each state a second, non-colour encoding.
  o += "          <pattern id=\"hatch-deg\" width=\"7\" height=\"7\""
       " patternUnits=\"userSpaceOnUse\" patternTransform=\"rotate(45)\">\n"
       "            <line x1=\"0\" y1=\"0\" x2=\"0\" y2=\"7\" class=\"hatch-stroke\"/>\n"
       "          </pattern>\n";
  o += "          <pattern id=\"hatch-den\" width=\"5\" height=\"5\""
       " patternUnits=\"userSpaceOnUse\" patternTransform=\"rotate(45)\">\n"
       "            <line x1=\"0\" y1=\"0\" x2=\"0\" y2=\"5\" class=\"hatch-stroke\"/>\n"
       "            <line x1=\"2.5\" y1=\"0\" x2=\"2.5\" y2=\"5\" class=\"hatch-stroke\""
       " stroke-width=\"0.7\"/>\n          </pattern>\n";
  o += "        </defs>\n        <g id=\"plot\"></g>\n      </svg>\n    </div>\n\n";

  o += "    <div class=\"legend\" role=\"list\">\n";
  o += "      <span class=\"legend-item\" role=\"listitem\">"
       "<span class=\"swatch\" style=\"background: var(--ok)\"></span> served</span>\n";
  o += "      <span class=\"legend-item\" role=\"listitem\">"
       "<span class=\"swatch\" style=\"background: var(--degraded); background-image:"
       " repeating-linear-gradient(45deg, transparent 0 3px, var(--surface) 3px 4px)\">"
       "</span> degraded &gt; " + group(m.degraded_above_ms) + " ms</span>\n";
  o += "      <span class=\"legend-item\" role=\"listitem\">"
       "<span class=\"swatch\" style=\"background: var(--denied); background-image:"
       " repeating-linear-gradient(45deg, transparent 0 2px, var(--surface) 2px 3px)\">"
       "</span> no response</span>\n";
  o += "    </div>\n\n";
  o += "    <div class=\"markers\">\n" + markers_html(log, v) + "    </div>\n";
  o += "  </section>\n\n";

  // ---- event log ----
  o += "  <section class=\"card\">\n";
  o += "    <div class=\"card-head\"><h2>Event log</h2></div>\n";
  o += "    <div class=\"table-scroll\">\n      <table>\n";
  o += "        <caption>Every state change, and the measurement that triggered"
       " it.</caption>\n";
  o += "        <thead><tr><th scope=\"col\">Time</th><th scope=\"col\">State</th>"
       "<th scope=\"col\">Event</th><th scope=\"col\">Detail</th></tr></thead>\n";
  o += "        <tbody>\n";
  for (const auto& n : log.notes) {
    o += "          <tr><td class=\"t\">" + num(n.t, 1) + " s</td><td>"
         "<span class=\"pill " + pill_for(n.state) + "\">" +
         availability_name(n.state) + "</span></td><td>" + esc(n.title) +
         "</td><td>" + esc(n.detail) + "</td></tr>\n";
  }
  o += "        </tbody>\n      </table>\n    </div>\n  </section>\n\n";

  // ---- capacity ----
  o += "  <section class=\"card\">\n    <div class=\"card-head\">\n";
  o += "      <h2>Capacity search</h2>\n";
  o += "      <p class=\"card-note\">Connections are held at each level and probed"
       " before stepping up, so the resolution is the step size rather than an"
       " accident of ramp timing.</p>\n    </div>\n";
  o += "    <div class=\"bracket\">\n";
  o += "      <span class=\"bracket-label\">Denial threshold</span>\n";
  if (v.threshold_measured) {
    o += "      <span class=\"bracket-value\">" + std::to_string(v.threshold_lo) +
         " &lt; n &le; " + std::to_string(v.threshold_hi) + "</span>\n";
    o += "      <span class=\"bracket-note\">connections · step " +
         std::to_string(v.threshold_step) + "</span>\n";
  } else {
    o += "      <span class=\"bracket-value muted\">not measured</span>\n";
    o += "      <span class=\"bracket-note\">" + esc(v.threshold_note) + "</span>\n";
  }
  o += "    </div>\n";
  if (!log.capacity.empty()) {
    o += "    <div class=\"table-scroll\">\n      <table>\n";
    o += "        <thead><tr><th scope=\"col\">Level</th><th scope=\"col\">Held for</th>"
         "<th scope=\"col\">Probes served</th><th scope=\"col\">Median latency</th>"
         "<th scope=\"col\">Result</th></tr></thead>\n        <tbody>\n";
    for (const auto& c : log.capacity) {
      o += "          <tr><td class=\"t\">" + std::to_string(c.connections) +
           "</td><td class=\"t\">" + num(c.hold_s, 0) + " s</td><td>" +
           std::to_string(c.probes_served) + " / " + std::to_string(c.probes_total) +
           "</td><td>" + (c.median_ms < 0 ? "—" : group(c.median_ms) + " ms") +
           "</td><td><span class=\"pill " + (c.denied ? "den" : "ok") + "\">" +
           (c.denied ? "denied" : "held") + "</span></td></tr>\n";
    }
    o += "        </tbody>\n      </table>\n    </div>\n";
  }
  o += "  </section>\n\n";

  // ---- parameters ----
  o += "  <section class=\"card\">\n";
  o += "    <div class=\"card-head\"><h2>Test parameters</h2></div>\n";
  o += "    <dl class=\"params\">\n";
  auto param = [&o](const std::string& k, const std::string& val) {
    o += "      <div class=\"param\"><dt>" + k + "</dt><dd>" + val + "</dd></div>\n";
  };
  param("Target", esc(m.target_url));
  param("Mode", esc(m.mode_label) + " (" + esc(m.mode_flag) + ")");
  param("Connections", std::to_string(m.connections));
  param("Connection rate", std::to_string(m.rate) + " / s");
  param("Duration", std::to_string(m.duration_s) + " s");
  if (m.mode_flag == "-X") {
    param("Read interval", std::to_string(m.read_interval_s) + " s (-n)");
    param("Read size", std::to_string(m.read_len) + " B (-z)");
    param("Advertised window", std::to_string(m.window_lower) + "–" +
                                   std::to_string(m.window_upper) + " B requested");
    if (m.kernel_rcvbuf >= 0)
      param("Kernel SO_RCVBUF", group(m.kernel_rcvbuf) + " B actual");
  } else {
    param("Followup interval", std::to_string(m.interval_s) + " s (-i)");
  }
  param("Probe interval", num(m.probe_interval_ms / 1000.0, 1) + " s");
  param("Probe timeout", num(m.probe_timeout_ms / 1000.0, 1) + " s (-p)");
  param("Degraded above", group(m.degraded_above_ms) + " ms");
  param("Baseline latency",
        m.baseline_ms < 0 ? "not measured" : group(m.baseline_ms) + " ms");
  if (!m.user_agent.empty()) param("User agent", esc(m.user_agent));
  if (!m.fail_on_status_spec.empty())
    param("Fail on status", esc(m.fail_on_status_spec) + " (CI gate only)");
  if (m.extra_header_count > 0) {
    // The count, never the values: -1 headers routinely carry bearer tokens, and
    // a report is a file people attach to tickets.
    param("Custom headers", std::to_string(m.extra_header_count) +
                                " sent on every request and probe");
  }
  if (!m.body_data_source.empty())
    param("Request body", esc(m.body_data_source) + " (-P)");
  if (!m.tls_description.empty()) param("TLS", esc(m.tls_description));
  if (!m.proxy.empty()) param("Proxy (-d)", esc(m.proxy));
  if (!m.probe_proxy.empty()) param("Probe proxy (-e)", esc(m.probe_proxy));
  o += "    </dl>\n  </section>\n\n";

  // ---- footer ----
  o += "  <footer>\n";
  o += "    <div>Generated by <code>slowhttptest-ng</code> · exit code <code>" +
       std::to_string(log.exit_code) +
       "</code> · machine-readable companion carries <code>\"outcome\": \"" +
       outcome_name(v.outcome) + "\"</code> and <code>\"pass\": " +
       (v.criterion_pass ? "true" : "false") +
       "</code> against an availability threshold of <code>" +
       num(v.criterion_threshold * 100, 0) + "%</code> (measured " +
       num(v.availability * 100, 1) + "%).</div>\n";
  o += "    <div>Outcome is one of <code>denied</code>, <code>degraded</code>,"
       " <code>held</code>, or <code>inconclusive</code> — the last when the"
       " baseline was already unhealthy or too few probes landed to justify a"
       " conclusion.</div>\n";
  o += "    <div>Run only against systems you are authorized to test.</div>\n";
  o += "  </footer>\n</div>\n\n";

  o += "<div id=\"tip\" role=\"status\" aria-live=\"polite\"></div>\n\n";
  o += "<script>\n" + embed_data(log, v) + "</script>\n";
  o += "<script>";
  o += kScript;
  o += "</script>\n</body>\n</html>\n";
  return o;
}

void print_verdict(std::FILE* out, const Verdict& v, const EventLog& log) {
  const OutcomeStyle st = style_for(v.outcome);
  std::fprintf(out, "\n%s — %s\n", st.word, v.scope.c_str());
  std::fprintf(out, "%s\n", v.summary.c_str());
  std::fprintf(out,
               "\nprobes: %d served, %d degraded, %d denied (%.1f%% availability,"
               " threshold %.0f%% -> %s)\n",
               v.probes_served, v.probes_degraded, v.probes_denied,
               v.availability * 100.0, v.criterion_threshold * 100.0,
               v.criterion_pass ? "PASS" : "FAIL");
  if (v.probes_failing_status > 0) {
    // Otherwise a run reading "SERVICE HELD ... 100% availability -> FAIL" looks
    // self-contradictory. It isn't: the gate is a separate, opt-in policy.
    std::fprintf(out,
                 "  ^ %d probe(s) answered with a status matching"
                 " --fail-on-status %s. This fails the CI gate only; the service"
                 " did answer, so the measured outcome is unchanged.\n",
                 v.probes_failing_status, log.meta.fail_on_status_spec.c_str());
  }
  if (log.meta.baseline_ms >= 0)
    std::fprintf(out, "baseline: %ld ms; degraded above %ld ms\n",
                 log.meta.baseline_ms, log.meta.degraded_above_ms);
  if (v.threshold_measured) {
    std::fprintf(out, "denial threshold: %d < n <= %d connections (step %d)\n",
                 v.threshold_lo, v.threshold_hi, v.threshold_step);
  } else if (!v.threshold_note.empty()) {
    std::fprintf(out, "denial threshold: %s\n", v.threshold_note.c_str());
  }
  std::fprintf(out, "\nnot ruled out:\n");
  for (const auto& c : v.caveats) std::fprintf(out, "  - %s\n", c.c_str());
}

bool write_reports(const Config& cfg, const EventLog& log, const Verdict& v) {
  bool ok = true;
  const std::string html_path = cfg.report_base + ".html";
  const std::string json_path = cfg.report_base + ".json";

  struct Out {
    const std::string& path;
    std::string body;
  };
  const Out outs[] = {{html_path, render_html(log, v)},
                      {json_path, render_json(log, v)}};

  for (const auto& f : outs) {
    // open(2) with an explicit mode rather than fopen(3), which always asks for
    // 0666 and leaves the result entirely to the caller's umask -- so a umask of
    // 0 yields a world-writable report. A report names the target host and the
    // shape of the run, which is not something to hand to every local account.
    // 0644 is still masked by umask, so a stricter one keeps producing 0600.
    const int fd =
        ::open(f.path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    std::FILE* fp = fd < 0 ? nullptr : ::fdopen(fd, "wb");
    if (!fp) {
      if (fd >= 0) ::close(fd);
      std::fprintf(stderr, "Error: cannot write %s\n", f.path.c_str());
      ok = false;
      continue;
    }
    const size_t n = std::fwrite(f.body.data(), 1, f.body.size(), fp);
    const bool short_write = n != f.body.size();
    if (std::fclose(fp) != 0 || short_write) {
      std::fprintf(stderr, "Error: failed while writing %s\n", f.path.c_str());
      ok = false;
      continue;
    }
    if (cfg.log_level >= 1)
      std::fprintf(stderr, "wrote %s (%zu bytes)\n", f.path.c_str(),
                   f.body.size());
  }
  return ok;
}

}  // namespace slowhttp
