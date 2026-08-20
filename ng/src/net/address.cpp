// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "net/address.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>

namespace slowhttp {

ResolvedAddr::~ResolvedAddr() {
  if (list_) ::freeaddrinfo(list_);
}

bool ResolvedAddr::resolve(const std::string& host, const std::string& port,
                           std::string& error, int family) {
  addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = family != 0 ? family : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;  // TCP
  hints.ai_protocol = IPPROTO_TCP;

  int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &list_);
  if (rc != 0) {
    error = ::gai_strerror(rc);
    list_ = nullptr;
    return false;
  }
  for (addrinfo* ai = list_; ai != nullptr; ai = ai->ai_next)
    candidates_.push_back(ai);
  if (candidates_.empty()) {
    error = family == AF_INET
                ? "no IPv4 address for this host"
                : family == AF_INET6 ? "no IPv6 address for this host"
                                     : "resolver returned no usable addresses";
    return false;
  }
  return true;
}

std::string ResolvedAddr::describe(const addrinfo* ai) {
  if (ai == nullptr) return "<none>";
  char host[NI_MAXHOST] = {0};
  char serv[NI_MAXSERV] = {0};
  int rc = ::getnameinfo(ai->ai_addr, ai->ai_addrlen, host, sizeof(host), serv,
                         sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
  if (rc != 0) return "<unprintable>";
  std::string h(host);
  // Bracket IPv6 literals so "::1:8080" doesn't read ambiguously.
  if (h.find(':') != std::string::npos) h = "[" + h + "]";
  return h + ":" + serv;
}

}  // namespace slowhttp
