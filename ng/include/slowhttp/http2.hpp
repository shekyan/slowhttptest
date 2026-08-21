// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_HTTP2_HPP_
#define SLOWHTTP_HTTP2_HPP_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// Just enough HTTP/2 to *send* a request, and nothing more.
//
// The attacks this serves never read a frame: slow read exists precisely to not
// drain the connection, and the internal-buffering variant it targets works by
// telling the server it may send a great deal and then never accepting it. So
// there is no frame parser here, no HPACK decoder, and no dynamic table --
// those are what make an HTTP/2 implementation large, and none of them are
// needed to hold a stream open.
//
// Everything below is byte-exact against RFC 7540 (framing) and RFC 7541
// (HPACK), and covered by tests that assert the encoded bytes rather than the
// behaviour, because a framing bug against a real server looks identical to a
// server that simply ignored us.
namespace slowhttp {
namespace http2 {

// RFC 7540 section 3.5. Sent by the client before anything else, on both h2 and
// h2c. It is deliberately not valid HTTP/1.1, so a server that only speaks 1.1
// rejects it rather than misinterpreting it.
extern const char* const kPreface;

enum class FrameType : std::uint8_t {
  Data = 0x0,
  Headers = 0x1,
  RstStream = 0x3,
  Settings = 0x4,
  WindowUpdate = 0x8,
};

// Frame flags, per type. END_STREAM and END_HEADERS share a byte position with
// other flags on other frame types, which is why they are named by frame.
enum : std::uint8_t {
  kFlagNone = 0x0,
  kFlagEndStream = 0x1,   // DATA, HEADERS
  kFlagAck = 0x1,         // SETTINGS, PING
  kFlagEndHeaders = 0x4,  // HEADERS, CONTINUATION
};

enum : std::uint16_t {
  kSettingsEnablePush = 0x2,
  kSettingsMaxConcurrentStreams = 0x3,
  kSettingsInitialWindowSize = 0x4,
};

// The largest a flow-control window may be. RFC 7540 section 6.9.1: a value
// above this is a FLOW_CONTROL_ERROR, so this is what "open the window as far
// as it will go" means.
constexpr std::uint32_t kMaxWindow = 0x7fffffffu;

// Appends one frame -- 9-byte header then payload -- to `out`.
//
// The length field is 24 bits and the stream id 31, with the top bit of the id
// reserved and required to be zero; both are masked here so a caller cannot
// produce a frame that is malformed in a way a server would read as something
// else entirely.
void write_frame(std::string& out, FrameType type, std::uint8_t flags,
                 std::uint32_t stream_id, const std::string& payload);

// SETTINGS payload: six bytes per entry, a 16-bit identifier and a 32-bit
// value. Unknown identifiers must be ignored by the peer, so this does not
// validate them.
std::string settings_payload(
    const std::vector<std::pair<std::uint16_t, std::uint32_t>>& entries);

// WINDOW_UPDATE payload: a 31-bit increment with the top bit reserved. An
// increment of zero is a protocol error, so callers must not pass one.
std::string window_update_payload(std::uint32_t increment);

// RST_STREAM payload: a 32-bit error code.
std::string rst_stream_payload(std::uint32_t error_code);

// Appends one header as an HPACK "literal header field without indexing --
// new name" (RFC 7541 section 6.2.2): a zero byte, then name and value each as
// a length-prefixed string.
//
// Never indexed and never Huffman-coded. That costs bytes on the wire and buys
// something worth more here: the encoder holds no state, so every request is
// independent and a connection cannot be desynchronised by a table mistake.
// Header names must already be lowercase -- uppercase is malformed in HTTP/2
// (RFC 7540 section 8.1.2) and servers reset the stream for it.
void hpack_literal(std::string& out, const std::string& name,
                   const std::string& value);

// HPACK integer with an N-bit prefix (RFC 7541 section 5.1). Exposed for tests;
// callers normally want hpack_literal.
void hpack_integer(std::string& out, std::uint32_t value, int prefix_bits,
                   std::uint8_t prefix_value);

}  // namespace http2
}  // namespace slowhttp

#endif  // SLOWHTTP_HTTP2_HPP_
