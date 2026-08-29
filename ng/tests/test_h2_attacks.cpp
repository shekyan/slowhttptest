// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the three HTTP/2 attack state machines: slow read over
// HTTP/2, rapid reset, and the CONTINUATION flood.
//
// e2e_http2.py proves each attack against a peer that enforces the protocol;
// what only a hermetic test can pin down is the *shape* of what they emit --
// the handshake ordering, the HEADERS/RST_STREAM pairing that is the whole of
// rapid reset, and the never-completed header block that is the whole of the
// CONTINUATION flood. Those are one refactor away from silently becoming
// something else: an ordinary client, or a different attack wearing the name.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "slowhttp/attacks/continuation.hpp"
#include "slowhttp/attacks/rapid_reset.hpp"
#include "slowhttp/attacks/slow_read_h2.hpp"
#include "slowhttp/http2.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::http2::FrameType;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

// One frame off the wire, minimally parsed: enough to assert type, flags,
// stream id and payload size without pretending this is a decoder.
struct Frame {
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::uint32_t stream = 0;
  std::string payload;
};

static std::uint8_t octet(const std::string& s, std::size_t i) {
  return static_cast<std::uint8_t>(s[i]);
}

// Splits the bytes after the connection preface into frames. Returns whatever
// parsed cleanly; a truncated tail is dropped, which is fine here -- the
// attacks emit whole frames by construction and the test says so if not.
static std::vector<Frame> parse_frames(const std::string& wire,
                                       std::size_t skip) {
  std::vector<Frame> out;
  std::size_t i = skip;
  while (i + 9 <= wire.size()) {
    Frame f;
    const std::uint32_t len = (static_cast<std::uint32_t>(octet(wire, i)) << 16) |
                              (static_cast<std::uint32_t>(octet(wire, i + 1)) << 8) |
                              static_cast<std::uint32_t>(octet(wire, i + 2));
    if (i + 9 + len > wire.size()) break;
    f.type = octet(wire, i + 3);
    f.flags = octet(wire, i + 4);
    f.stream = ((static_cast<std::uint32_t>(octet(wire, i + 5)) << 24) |
                (static_cast<std::uint32_t>(octet(wire, i + 6)) << 16) |
                (static_cast<std::uint32_t>(octet(wire, i + 7)) << 8) |
                static_cast<std::uint32_t>(octet(wire, i + 8))) &
               0x7fffffffu;
    f.payload = wire.substr(i + 9, len);
    out.push_back(f);
    i += 9 + len;
  }
  return out;
}

static Config h2_config() {
  Config cfg;
  cfg.connections = 2;
  cfg.target.scheme = "https";
  cfg.target.host = "example.test";
  cfg.target.path = "/";
  cfg.user_agent = "slowhttptest-ng-unit";
  cfg.max_random_data_len = 8;
  return cfg;
}

static bool starts_with_preface(const std::string& s) {
  const std::string p = slowhttp::http2::kPreface;
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

// A SETTINGS payload entry is a 16-bit id and a 32-bit value, big-endian.
static bool settings_has(const Frame& f, std::uint16_t id, std::uint32_t value) {
  if (f.payload.size() % 6 != 0) return false;
  for (std::size_t i = 0; i + 6 <= f.payload.size(); i += 6) {
    const std::uint16_t got_id = static_cast<std::uint16_t>(
        (octet(f.payload, i) << 8) | octet(f.payload, i + 1));
    const std::uint32_t got_val =
        (static_cast<std::uint32_t>(octet(f.payload, i + 2)) << 24) |
        (static_cast<std::uint32_t>(octet(f.payload, i + 3)) << 16) |
        (static_cast<std::uint32_t>(octet(f.payload, i + 4)) << 8) |
        static_cast<std::uint32_t>(octet(f.payload, i + 5));
    if (got_id == id && got_val == value) return true;
  }
  return false;
}

static bool payload_is_u32(const Frame& f, std::uint32_t value) {
  return f.payload.size() == 4 &&
         static_cast<std::uint32_t>(octet(f.payload, 0)) == (value >> 24) &&
         static_cast<std::uint32_t>(octet(f.payload, 1)) == ((value >> 16) & 0xff) &&
         static_cast<std::uint32_t>(octet(f.payload, 2)) == ((value >> 8) & 0xff) &&
         static_cast<std::uint32_t>(octet(f.payload, 3)) == (value & 0xff);
}

// --------------------------------------------------------------------------
// Slow read over HTTP/2 (CVE-2019-9517): open both flow-control windows, then
// ask for responses and never accept them.
// --------------------------------------------------------------------------
static void test_slow_read_h2() {
  Config cfg = h2_config();
  cfg.h2_streams = 3;
  cfg.read_interval = std::chrono::seconds(2);
  cfg.read_len = 7;
  cfg.window_lower = 4;
  cfg.window_upper = 9;

  slowhttp::SlowReadH2 atk(cfg);
  check(!atk.wants_read_events(),
        "h2 slow read does not watch for readability (draining is the opposite"
        " of the attack)");

  const slowhttp::ConnOptions co = atk.conn_options(0);
  check(co.recv_buffer >= 4 && co.recv_buffer <= 9,
        "advertised window is drawn from [-w, -y]");

  atk.on_open(0);
  const Action a = atk.on_connect(0);
  check(a.kind == Action::Kind::Send, "on_connect sends the opening burst");
  check(a.rearm && *a.rearm == std::chrono::milliseconds(2000),
        "the first sip is scheduled at the read interval");
  check(starts_with_preface(a.bytes), "the burst starts with the client preface");

  const std::vector<Frame> frames =
      parse_frames(a.bytes, std::string(slowhttp::http2::kPreface).size());
  // SETTINGS, connection WINDOW_UPDATE, then one HEADERS per stream.
  check(frames.size() == 2 + static_cast<std::size_t>(cfg.h2_streams),
        "settings + window update + one HEADERS per --h2-streams");
  if (frames.size() == 2 + static_cast<std::size_t>(cfg.h2_streams)) {
    check(frames[0].type == static_cast<std::uint8_t>(FrameType::Settings) &&
              frames[0].stream == 0,
          "first frame is SETTINGS on stream 0");
    check(settings_has(frames[0], slowhttp::http2::kSettingsInitialWindowSize,
                       slowhttp::http2::kMaxWindow),
          "SETTINGS opens the stream window to the protocol maximum");
    check(settings_has(frames[0], slowhttp::http2::kSettingsEnablePush, 0),
          "SETTINGS refuses server push");
    check(frames[1].type == static_cast<std::uint8_t>(FrameType::WindowUpdate) &&
              frames[1].stream == 0,
          "second frame is a connection-level WINDOW_UPDATE");
    check(frames[1].payload.size() == 4,
          "connection WINDOW_UPDATE carries a 4-byte increment");
    for (int i = 0; i < cfg.h2_streams; ++i) {
      const Frame& h = frames[2 + static_cast<std::size_t>(i)];
      check(h.type == static_cast<std::uint8_t>(FrameType::Headers),
            "request frames are HEADERS");
      check(h.stream == 1u + 2u * static_cast<unsigned>(i),
            "stream ids are odd and ascend");
      check(h.flags ==
                static_cast<std::uint8_t>(slowhttp::http2::kFlagEndStream |
                                          slowhttp::http2::kFlagEndHeaders),
            "each request is complete (END_STREAM|END_HEADERS), so the server"
            " may start answering into the buffers it will not drain");
    }
  }

  const Action t = atk.on_timer(0);
  check(t.kind == Action::Kind::Read && t.read_bytes == 7,
        "the timer sips exactly -z bytes");
  check(t.rearm && *t.rearm == std::chrono::milliseconds(2000),
        "sips re-arm at the read interval");
}

// --------------------------------------------------------------------------
// Rapid reset (CVE-2023-44487): HEADERS immediately followed by RST_STREAM on
// the same stream, repeatedly. The pairing is the attack; anything else is a
// different attack wearing the name.
// --------------------------------------------------------------------------
static void test_rapid_reset() {
  Config cfg = h2_config();
  cfg.h2_reset_rate = 100;  // per second, per connection

  slowhttp::RapidReset atk(cfg);
  check(atk.wants_read_events(), "rapid reset drains and discards responses");
  check(atk.tick() == std::chrono::milliseconds(100),
        "bursts land on a 100ms tick");
  check(atk.per_tick() == 10, "rate 100/s over 10 ticks is 10 streams per tick");

  atk.on_open(0);
  const Action a = atk.on_connect(0);
  check(a.kind == Action::Kind::Send, "on_connect sends preface and first burst");
  check(a.rearm && *a.rearm == std::chrono::milliseconds(100),
        "the next burst is scheduled one tick out");
  check(starts_with_preface(a.bytes), "the burst starts with the client preface");

  const std::vector<Frame> frames =
      parse_frames(a.bytes, std::string(slowhttp::http2::kPreface).size());
  check(frames.size() == 1 + 2u * static_cast<std::size_t>(atk.per_tick()),
        "SETTINGS then a HEADERS/RST_STREAM pair per stream");
  if (frames.size() == 1 + 2u * static_cast<std::size_t>(atk.per_tick())) {
    check(frames[0].type == static_cast<std::uint8_t>(FrameType::Settings),
          "first frame is SETTINGS");
    check(settings_has(frames[0], slowhttp::http2::kSettingsEnablePush, 0),
          "SETTINGS refuses server push");
    for (int i = 0; i < atk.per_tick(); ++i) {
      const Frame& h = frames[1 + 2u * static_cast<std::size_t>(i)];
      const Frame& r = frames[2 + 2u * static_cast<std::size_t>(i)];
      check(h.type == static_cast<std::uint8_t>(FrameType::Headers) &&
                r.type == static_cast<std::uint8_t>(FrameType::RstStream),
            "HEADERS is immediately followed by RST_STREAM");
      check(h.stream == r.stream,
            "the reset targets the stream that was just opened");
      check(h.stream % 2 == 1 && h.stream >= 1,
            "client stream ids are odd, starting at 1");
      check(h.flags ==
                static_cast<std::uint8_t>(slowhttp::http2::kFlagEndStream |
                                          slowhttp::http2::kFlagEndHeaders),
            "the request is complete before it is cancelled");
      check(payload_is_u32(r, 0x8), "the reset error code is CANCEL (0x8)");
    }
  }
  check(atk.streams_reset() == atk.per_tick(),
        "the counter matches the frames emitted");

  const Action t = atk.on_timer(0);
  check(t.kind == Action::Kind::Send && t.bytes.size() > 9,
        "each tick emits another burst of frames");
  check(atk.streams_reset() == 2 * atk.per_tick(),
        "the counter keeps counting across bursts");

  const Action rd = atk.on_readable(0, "GOAWAY", 6);
  check(rd.kind == Action::Kind::Idle,
        "server bytes are read and ignored; only the close matters");
}

// --------------------------------------------------------------------------
// CONTINUATION flood: one HEADERS frame with no END_HEADERS, then
// CONTINUATION frames that also never close the block. Completing it, even
// once, hands the server a well-formed request and turns the attack into an
// ordinary slow client.
// --------------------------------------------------------------------------
static void test_continuation_flood() {
  Config cfg = h2_config();
  cfg.interval = std::chrono::seconds(3);

  slowhttp::ContinuationFlood atk(cfg);
  check(!atk.wants_read_events(), "the flood does not drain the socket");

  atk.on_open(0);
  const Action a = atk.on_connect(0);
  check(a.kind == Action::Kind::Send, "on_connect sends the opening");
  check(a.rearm && *a.rearm == std::chrono::milliseconds(3000),
        "fragments are spaced by -i");
  check(starts_with_preface(a.bytes), "the opening starts with the preface");

  const std::vector<Frame> frames =
      parse_frames(a.bytes, std::string(slowhttp::http2::kPreface).size());
  check(frames.size() == 2, "SETTINGS then exactly one HEADERS");
  if (frames.size() == 2) {
    check(frames[0].type == static_cast<std::uint8_t>(FrameType::Settings),
          "first frame is SETTINGS");
    check(frames[1].type == static_cast<std::uint8_t>(FrameType::Headers) &&
              frames[1].stream == 1,
          "one HEADERS on stream 1");
    check(frames[1].flags == 0,
          "the HEADERS sets neither END_STREAM nor END_HEADERS -- the header"
          " block is left open, which is the attack");
  }

  const Action t = atk.on_timer(0);
  check(t.kind == Action::Kind::Send && t.rearm, "on_timer dribbles a fragment");
  const std::vector<Frame> frag = parse_frames(t.bytes, 0);
  check(frag.size() == 1 &&
            frag[0].type == static_cast<std::uint8_t>(FrameType::Continuation) &&
            frag[0].stream == 1,
        "the followup is a single CONTINUATION on the same stream");
  if (frag.size() == 1) {
    check(frag[0].flags == 0, "CONTINUATION never sets END_HEADERS");
    check(frag[0].payload.size() > 0, "the fragment carries header bytes");
  }
  check(atk.fragments_sent() == 1, "the fragment counter counts");

  const Action rd = atk.on_readable(0, "x", 1);
  check(rd.kind == Action::Kind::Idle,
        "a server response is left uninterpreted; the close is the signal");
}

// -1 and -j exist so a run can address an authenticated or tenant-routed
// endpoint. They reached the HTTP/1.1 attacks and none of the HTTP/2 ones, so
// an h2 run silently attacked a different endpoint from the one the operator
// named. Every h2 attack must carry them, including the CONTINUATION flood,
// whose block is never completed but is still read as it arrives.
static bool headers_contain(const std::string& wire, const std::string& needle) {
  const std::vector<Frame> frames =
      parse_frames(wire, std::string(slowhttp::http2::kPreface).size());
  for (const auto& f : frames)
    if (f.type == static_cast<std::uint8_t>(FrameType::Headers) &&
        f.payload.find(needle) != std::string::npos)
      return true;
  return false;
}

static void test_h2_carries_caller_headers() {
  Config cfg = h2_config();
  cfg.h2_streams = 1;
  cfg.cookie = "session=abc123";
  cfg.extra_headers.push_back("Authorization: Bearer tok-42");
  cfg.extra_headers.push_back("X-Tenant: acme");
  // Malformed in HTTP/2; a server may reset the stream for it, which would look
  // like the attack landing.
  cfg.extra_headers.push_back("Connection: keep-alive");

  struct Case {
    const char* name;
    std::string wire;
  };
  std::vector<Case> cases;
  {
    slowhttp::SlowReadH2 a(cfg);
    a.on_open(0);
    cases.push_back({"slow read h2", a.on_connect(0).bytes});
  }
  {
    slowhttp::RapidReset a(cfg);
    a.on_open(0);
    cases.push_back({"rapid reset", a.on_connect(0).bytes});
  }
  {
    slowhttp::ContinuationFlood a(cfg);
    a.on_open(0);
    cases.push_back({"continuation flood", a.on_connect(0).bytes});
  }

  for (const auto& c : cases) {
    check(headers_contain(c.wire, "authorization"),
          (std::string(c.name) + ": -1 header name reaches the request").c_str());
    check(headers_contain(c.wire, "Bearer tok-42"),
          (std::string(c.name) + ": -1 header value reaches the request").c_str());
    check(headers_contain(c.wire, "x-tenant"),
          (std::string(c.name) + ": a second -1 header is not dropped").c_str());
    check(headers_contain(c.wire, "session=abc123"),
          (std::string(c.name) + ": -j cookie reaches the request").c_str());
    check(!headers_contain(c.wire, "keep-alive"),
          (std::string(c.name) +
           ": connection-specific headers are dropped, not encoded").c_str());
    check(!headers_contain(c.wire, "Authorization"),
          (std::string(c.name) +
           ": header names are lowercased as HTTP/2 requires").c_str());
  }
}

int main() {
  test_slow_read_h2();
  test_rapid_reset();
  test_continuation_flood();
  test_h2_carries_caller_headers();
  if (failures == 0) std::fprintf(stderr, "h2 attacks: all checks passed\n");
  return failures == 0 ? 0 : 1;
}
