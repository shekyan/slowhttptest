// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_NET_ADDRESS_HPP_
#define SLOWHTTP_NET_ADDRESS_HPP_

#include <string>
#include <vector>

struct addrinfo;

namespace slowhttp {

// Owns the result of getaddrinfo() and frees it on destruction.
class ResolvedAddr {
 public:
  ResolvedAddr() = default;
  ~ResolvedAddr();
  ResolvedAddr(const ResolvedAddr&) = delete;
  ResolvedAddr& operator=(const ResolvedAddr&) = delete;

  // Resolves host/port to a TCP addrinfo list. Returns false on failure and sets
  // `error`.
  // `family` is AF_UNSPEC, AF_INET or AF_INET6.
  bool resolve(const std::string& host, const std::string& port,
               std::string& error, int family = 0);

  // First usable entry, or nullptr if unresolved.
  const addrinfo* first() const { return list_; }

  // Every resolved candidate, in the order the resolver returned them. A host
  // like "localhost" commonly resolves to ::1 *before* 127.0.0.1, so a client
  // that only ever tries the first entry fails against an IPv4-only listener.
  // Callers must be able to fall back through the whole list.
  const std::vector<const addrinfo*>& candidates() const { return candidates_; }

  // Human-readable "host:port" for a candidate, for diagnostics.
  static std::string describe(const addrinfo* ai);

 private:
  addrinfo* list_ = nullptr;
  std::vector<const addrinfo*> candidates_;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_NET_ADDRESS_HPP_
