// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// One description of the request, serialized per protocol.
//
// Every attack used to rebuild request semantics itself: the four HTTP/1.1 ones
// each wrote the same request line, Host, User-Agent and Accept, and the three
// HTTP/2 ones each wrote their own pseudo-header block. The probe made a fifth
// copy. They drifted, as parallel copies do -- the h2 attacks silently dropped
// every -1 header, so a run against an authenticated endpoint attacked the
// unauthenticated one and reported on that.
//
// The split this draws: RequestSpec says what the request *is*, the attack says
// how to abuse it. Withholding the final CRLF, promising a Content-Length it
// will not send, never closing the header block -- those are the attack's
// business. Which endpoint is addressed, and with whose credentials, is not.
#ifndef SLOWHTTP_REQUEST_HPP
#define SLOWHTTP_REQUEST_HPP

#include <string>
#include <utility>
#include <vector>

#include "slowhttp/config.hpp"

namespace slowhttp {

struct RequestSpec {
  std::string method;
  std::string scheme;         // "http" or "https"
  std::string authority;      // Host: and :authority
  std::string http11_target;  // origin-form, or absolute-form through a proxy
  std::string path;           // always origin-form, for :path

  // In the order they go on the wire. Names are written in canonical HTTP/1.1
  // case; the HTTP/2 serializer lowercases them, because h2 requires it.
  //
  // Host is deliberately NOT in here. It is derived from `authority` by both
  // serializers, so the two protocols cannot disagree about which host is being
  // addressed -- which is the failure this type exists to prevent.
  std::vector<std::pair<std::string, std::string>> headers;

  // The request the run is built around: verb, target, Host, User-Agent,
  // Accept, then the caller's Cookie, -1 headers and Referer.
  static RequestSpec from(const Config& cfg);

  // Appends, or replaces the value if the header is already present. Attacks
  // use this for the headers that *are* the attack -- Content-Length for slow
  // body, Range for the range attack.
  void set(const std::string& name, std::string value);

  // Request line and headers, each CRLF-terminated.
  //
  // The blank line that ends the header block is NOT appended. Whether the
  // request is finished is precisely what several of these attacks are lying
  // about, so it stays the caller's decision.
  std::string serialize_http11() const;

  // An HPACK block: pseudo-headers first and in the order RFC 7540 8.1.2.1
  // requires, then the rest with names lowercased.
  //
  // Connection-specific headers are dropped rather than encoded: they are
  // malformed in HTTP/2 (RFC 7540 8.1.2.2) and a server may reset the stream
  // for them, which under rapid reset looks exactly like the attack landing.
  std::string serialize_http2() const;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_REQUEST_HPP
