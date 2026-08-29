// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/request.hpp"

#include "slowhttp/http2.hpp"

namespace slowhttp {
namespace {

std::string lower(std::string s) {
  for (char& c : s)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return s;
}

bool iequal(const std::string& a, const std::string& b) {
  return lower(a) == lower(b);
}

// Malformed in HTTP/2 (RFC 7540 8.1.2.2). Names are compared lowercased.
bool connection_specific(const std::string& lowered) {
  return lowered == "connection" || lowered == "keep-alive" ||
         lowered == "proxy-connection" || lowered == "transfer-encoding" ||
         lowered == "upgrade" || lowered == "te";
}

}  // namespace

RequestSpec RequestSpec::from(const Config& cfg) {
  RequestSpec r;
  r.method = cfg.effective_verb();
  r.scheme = cfg.target.tls() ? "https" : "http";
  r.authority = cfg.target.host_header();
  r.http11_target = cfg.request_target();
  r.path = cfg.target.path;

  r.headers.emplace_back("User-Agent", cfg.user_agent);
  r.headers.emplace_back("Accept", cfg.accept);

  // The caller's own headers, last so they can override nothing by accident and
  // are visibly theirs. Cookie first to match how the HTTP/1.1 request has
  // always been laid out.
  if (!cfg.cookie.empty()) r.headers.emplace_back("Cookie", cfg.cookie);
  for (const auto& h : cfg.extra_headers) {
    const auto colon = h.find(':');
    // The CLI rejects a -1 value without a colon, so this cannot normally fire;
    // skipping rather than emitting a malformed line is the safe reading if it
    // ever does.
    if (colon == std::string::npos || colon == 0) continue;
    std::string name = h.substr(0, colon);
    std::string value = h.substr(colon + 1);
    std::size_t v = 0;
    while (v < value.size() && (value[v] == ' ' || value[v] == '\t')) ++v;
    value.erase(0, v);
    r.headers.emplace_back(std::move(name), std::move(value));
  }
  // Skipped when the operator supplied their own: some frameworks check Referer
  // for same-origin on POST, and a value they cannot parse gets the request
  // rejected before the attack can bite.
  if (!cfg.referer.empty() && !cfg.has_extra_header("Referer"))
    r.headers.emplace_back("Referer", cfg.referer);

  return r;
}

void RequestSpec::set(const std::string& name, std::string value) {
  for (auto& h : headers) {
    if (iequal(h.first, name)) {
      h.second = std::move(value);
      return;
    }
  }
  headers.emplace_back(name, std::move(value));
}

std::string RequestSpec::serialize_http11() const {
  std::string out;
  out.reserve(256 + headers.size() * 32);
  out += method;
  out += ' ';
  out += http11_target;
  out += " HTTP/1.1\r\n";
  out += "Host: " + authority + "\r\n";
  for (const auto& h : headers) out += h.first + ": " + h.second + "\r\n";
  return out;
}

std::string RequestSpec::serialize_http2() const {
  std::string block;
  // Pseudo-headers first and in this order; a server may reset the stream if
  // they are not.
  http2::hpack_literal(block, ":method", method);
  http2::hpack_literal(block, ":scheme", scheme);
  http2::hpack_literal(block, ":authority", authority);
  http2::hpack_literal(block, ":path", path);
  for (const auto& h : headers) {
    const std::string name = lower(h.first);
    if (connection_specific(name)) continue;
    http2::hpack_literal(block, name, h.second);
  }
  return block;
}

}  // namespace slowhttp
