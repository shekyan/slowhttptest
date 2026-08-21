// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Asserts the bytes, not the behaviour.
//
// A framing bug against a real server is invisible: the connection is accepted,
// nothing is sent back, and it looks exactly like a server that ignored us --
// which is also what a successful slow-read attack looks like. So the encoder is
// checked against the values written out in RFC 7540 and RFC 7541 rather than
// against anything that has to be running.
#include "slowhttp/http2.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;

std::string hex(const std::string& s) {
  static const char* d = "0123456789abcdef";
  std::string out;
  for (unsigned char c : s) {
    out.push_back(d[c >> 4]);
    out.push_back(d[c & 0xf]);
  }
  return out;
}

void expect_hex(const char* what, const std::string& got, const char* want) {
  if (hex(got) == want) return;
  std::fprintf(stderr, "FAIL %s\n  want %s\n  got  %s\n", what, want,
               hex(got).c_str());
  ++failures;
}

void expect(const char* what, bool ok) {
  if (ok) return;
  std::fprintf(stderr, "FAIL %s\n", what);
  ++failures;
}

}  // namespace

int main() {
  using namespace slowhttp::http2;

  // The preface is a fixed 24 octets and must be exactly this. Getting it wrong
  // is silently fatal: a server sees garbage and closes.
  expect("preface length", std::string(kPreface).size() == 24);
  expect_hex("preface", std::string(kPreface),
             "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a");

  // A frame header is 9 octets: 24-bit length, type, flags, 31-bit stream id.
  // An empty SETTINGS with the ACK flag is the smallest legal frame.
  {
    std::string out;
    write_frame(out, FrameType::Settings, kFlagAck, 0, "");
    expect_hex("empty SETTINGS ack", out, "000000040100000000");
  }

  // SETTINGS entries are 6 octets each: 16-bit id, 32-bit value. Opening the
  // initial window to its maximum is what makes the server generate a response
  // it will not be able to hand over.
  {
    const std::string payload = settings_payload(
        {{kSettingsInitialWindowSize, kMaxWindow}, {kSettingsEnablePush, 0}});
    expect("settings payload size", payload.size() == 12);
    expect_hex("settings payload", payload, "00047fffffff000200000000");

    std::string out;
    write_frame(out, FrameType::Settings, kFlagNone, 0, payload);
    expect_hex("SETTINGS frame", out,
               "00000c040000000000"
               "00047fffffff000200000000");
  }

  // WINDOW_UPDATE carries a 31-bit increment with the top bit reserved. Passing
  // a value with the top bit set must not produce a frame claiming a negative
  // window.
  {
    expect_hex("window update", window_update_payload(kMaxWindow), "7fffffff");
    expect_hex("window update masks reserved bit",
               window_update_payload(0xffffffffu), "7fffffff");
  }

  expect_hex("rst_stream CANCEL", rst_stream_payload(0x8), "00000008");

  // HPACK integers, using the examples from RFC 7541 appendix C.1.
  {
    std::string out;
    hpack_integer(out, 10, 5, 0x00);  // C.1.1: fits in the prefix
    expect_hex("hpack int 10 in 5 bits", out, "0a");

    out.clear();
    hpack_integer(out, 1337, 5, 0x00);  // C.1.2: spills into continuation bytes
    expect_hex("hpack int 1337 in 5 bits", out, "1f9a0a");

    out.clear();
    hpack_integer(out, 42, 8, 0x00);  // C.1.3
    expect_hex("hpack int 42 in 8 bits", out, "2a");
  }

  // A literal header without indexing and with a new name: 0x00, then each of
  // name and value as a 7-bit-prefixed length and its octets. RFC 7541 C.2.1
  // uses exactly this header.
  {
    std::string out;
    hpack_literal(out, "custom-key", "custom-header");
    expect_hex("hpack literal custom-key", out,
               "00"
               "0a" "637573746f6d2d6b6579"
               "0d" "637573746f6d2d686561646572");
  }

  // A header block long enough to need a two-byte length, which is where an
  // off-by-one in the integer encoder would first show.
  {
    const std::string value(200, 'x');
    std::string out;
    hpack_literal(out, "user-agent", value);
    // 0x00, name len 10, name, then 0x7f 0x49 for 200 (127 + 73), then 200 x's.
    expect("long value encodes to two length octets",
           out.size() == 1 + 1 + 10 + 2 + 200);
    expect("long value length prefix", static_cast<unsigned char>(out[12]) == 0x7f &&
                                       static_cast<unsigned char>(out[13]) == 0x49);
  }

  // A whole request as the attack sends it: pseudo-headers first, in the order
  // RFC 7540 section 8.1.2.1 requires, then ordinary headers.
  {
    std::string block;
    hpack_literal(block, ":method", "GET");
    hpack_literal(block, ":scheme", "https");
    hpack_literal(block, ":authority", "example.com");
    hpack_literal(block, ":path", "/");
    std::string frame;
    write_frame(frame, FrameType::Headers,
                static_cast<std::uint8_t>(kFlagEndStream | kFlagEndHeaders), 1,
                block);
    expect("headers frame carries the block", frame.size() == 9 + block.size());
    expect("headers frame type", static_cast<unsigned char>(frame[3]) == 0x01);
    expect("headers frame flags END_STREAM|END_HEADERS",
           static_cast<unsigned char>(frame[4]) == 0x05);
    expect("headers frame stream id 1",
           frame[5] == 0 && frame[6] == 0 && frame[7] == 0 && frame[8] == 1);
  }

  // Stream ids are 31 bits; the reserved top bit must never reach the wire.
  {
    std::string out;
    write_frame(out, FrameType::Data, kFlagNone, 0xffffffffu, "");
    expect("stream id masks reserved bit",
           static_cast<unsigned char>(out[5]) == 0x7f);
  }

  if (failures == 0) std::fprintf(stderr, "http2: all checks passed\n");
  return failures == 0 ? 0 : 1;
}
