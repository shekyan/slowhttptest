// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/http2.hpp"

namespace slowhttp {
namespace http2 {

const char* const kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

namespace {

void append_u24(std::string& out, std::uint32_t v) {
  out.push_back(static_cast<char>((v >> 16) & 0xff));
  out.push_back(static_cast<char>((v >> 8) & 0xff));
  out.push_back(static_cast<char>(v & 0xff));
}

void append_u32(std::string& out, std::uint32_t v) {
  out.push_back(static_cast<char>((v >> 24) & 0xff));
  out.push_back(static_cast<char>((v >> 16) & 0xff));
  out.push_back(static_cast<char>((v >> 8) & 0xff));
  out.push_back(static_cast<char>(v & 0xff));
}

void append_u16(std::string& out, std::uint16_t v) {
  out.push_back(static_cast<char>((v >> 8) & 0xff));
  out.push_back(static_cast<char>(v & 0xff));
}

}  // namespace

void write_frame(std::string& out, FrameType type, std::uint8_t flags,
                 std::uint32_t stream_id, const std::string& payload) {
  // Truncating rather than asserting: a payload this size cannot be produced by
  // anything in this tool, and a length field that disagrees with the bytes
  // that follow desynchronises the connection for good.
  const std::uint32_t len =
      static_cast<std::uint32_t>(payload.size()) & 0x00ffffffu;
  append_u24(out, len);
  out.push_back(static_cast<char>(type));
  out.push_back(static_cast<char>(flags));
  // Top bit is reserved and must be sent as zero.
  append_u32(out, stream_id & 0x7fffffffu);
  out.append(payload, 0, len);
}

std::string settings_payload(
    const std::vector<std::pair<std::uint16_t, std::uint32_t>>& entries) {
  std::string out;
  out.reserve(entries.size() * 6);
  for (const auto& e : entries) {
    append_u16(out, e.first);
    append_u32(out, e.second);
  }
  return out;
}

std::string window_update_payload(std::uint32_t increment) {
  std::string out;
  append_u32(out, increment & 0x7fffffffu);
  return out;
}

std::string rst_stream_payload(std::uint32_t error_code) {
  std::string out;
  append_u32(out, error_code);
  return out;
}

void hpack_integer(std::string& out, std::uint32_t value, int prefix_bits,
                   std::uint8_t prefix_value) {
  const std::uint32_t max_prefix = (1u << prefix_bits) - 1u;
  if (value < max_prefix) {
    out.push_back(static_cast<char>(prefix_value | value));
    return;
  }
  out.push_back(static_cast<char>(prefix_value | max_prefix));
  std::uint32_t rest = value - max_prefix;
  while (rest >= 128) {
    out.push_back(static_cast<char>((rest & 0x7f) | 0x80));
    rest >>= 7;
  }
  out.push_back(static_cast<char>(rest));
}

namespace {

// String literal: one bit saying whether it is Huffman-coded (always 0 here),
// then a 7-bit-prefix length, then the octets.
void hpack_string(std::string& out, const std::string& s) {
  hpack_integer(out, static_cast<std::uint32_t>(s.size()), 7, 0x00);
  out += s;
}

}  // namespace

void hpack_literal(std::string& out, const std::string& name,
                   const std::string& value) {
  out.push_back('\0');  // literal without indexing, new name
  hpack_string(out, name);
  hpack_string(out, value);
}

}  // namespace http2
}  // namespace slowhttp
