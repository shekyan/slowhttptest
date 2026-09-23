// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for the QUIC Initial packet layer.
//
// The key derivation is checked against the published vectors in RFC 9001
// Appendix A rather than against itself. That matters more here than usual: a
// self-consistent test would happily bless a wrong key schedule, and the only
// other feedback is a server silently dropping the packet.
#include <cstdio>
#include <cstdlib>
#include <string>

#include "slowhttp/quic.hpp"

using slowhttp::quic::Keys;
using slowhttp::quic::Reply;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

static std::string hex(const std::string& s) {
  std::string o;
  char b[3];
  for (unsigned char c : s) { std::snprintf(b, 3, "%02x", c); o += b; }
  return o;
}
static std::string unhex(const std::string& h) {
  std::string o;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2)
    o.push_back(static_cast<char>(std::stoi(h.substr(i, 2), nullptr, 16)));
  return o;
}
static unsigned be16(const std::string& s, std::size_t at) {
  return (static_cast<unsigned char>(s[at]) << 8) |
         static_cast<unsigned char>(s[at + 1]);
}

// Reads one RFC 9000 16 varint, advancing `at`.
static std::uint64_t get_varint(const std::string& s, std::size_t& at) {
  const unsigned char b = static_cast<unsigned char>(s[at]);
  const int n = 1 << (b >> 6);
  std::uint64_t v = b & 0x3f;
  for (int i = 1; i < n; ++i)
    v = (v << 8) | static_cast<unsigned char>(s[at + i]);
  at += n;
  return v;
}

static void test_rfc9001_appendix_a_keys() {
  // RFC 9001 A.1: the connection ID and every key derived from it.
  const std::string dcid = unhex("8394c8f03e515708");
  const Keys c = slowhttp::quic::initial_keys(dcid, /*server=*/false);
  const Keys s = slowhttp::quic::initial_keys(dcid, /*server=*/true);
  check(c.ok && s.ok, "keys derive at all");
  check(hex(c.key) == "1f369613dd76d5467730efcbe3b1a22d", "RFC 9001 A.1 client key");
  check(hex(c.iv) == "fa044b2f42a3fd3b46fb255c", "RFC 9001 A.1 client iv");
  check(hex(c.hp) == "9f50449e04a0e810283a1e9933adedd2", "RFC 9001 A.1 client hp");
  // The server's keys come from the same connection ID, which is what lets the
  // reply be read without any handshake state.
  check(hex(s.key) == "cf3a5331653c364c88f0f379b6067e37", "RFC 9001 A.1 server key");
  check(hex(s.iv) == "0ac1493ca1905853b0bba03e", "RFC 9001 A.1 server iv");
  check(hex(s.hp) == "c206b8d9b9f0f37644430b490eeaa314", "RFC 9001 A.1 server hp");
  check(c.key != s.key, "the two directions do not share a key");
}

static void test_varint_boundaries() {
  // Every boundary where the two-bit prefix changes width. Getting one wrong
  // shifts every field after it, and the server reports a decode error rather
  // than anything that looks like the attack working.
  struct { std::uint64_t v; std::size_t n; } cases[] = {
      {0, 1}, {63, 1}, {64, 2}, {16383, 2}, {16384, 4},
      {1073741823ULL, 4}, {1073741824ULL, 8}};
  for (auto& c : cases) {
    std::string out;
    slowhttp::quic::put_varint(out, c.v);
    check(out.size() == c.n, "varint width at a boundary");
    check(slowhttp::quic::varint_size(c.v) == c.n,
          "varint_size agrees with what put_varint writes");
    std::size_t at = 0;
    check(get_varint(out, at) == c.v, "varint round-trips");
  }
}

static void test_hello_is_quic_shaped() {
  slowhttp::quic::HelloOptions opt;
  opt.host = "example.test";
  opt.scid = std::string(8, 'S');
  const std::string h = slowhttp::quic::client_hello(opt);
  check(!h.empty(), "a hello is produced");
  check(static_cast<unsigned char>(h[0]) == 0x01, "it is a ClientHello");

  const std::size_t body = 4;                       // past the handshake header
  check(be16(h, body) == 0x0303, "legacy_version is TLS 1.2 as the RFC requires");
  // RFC 9001 8.4: a QUIC server MUST reject a non-empty legacy_session_id, so
  // the middlebox-compatibility trick used over TCP is forbidden here.
  check(static_cast<unsigned char>(h[body + 2 + 32]) == 0,
        "legacy_session_id is empty, which QUIC requires");

  std::size_t at = body + 2 + 32 + 1;
  at += 2 + be16(h, at);                            // cipher_suites
  at += 1 + static_cast<unsigned char>(h[at]);      // compression_methods
  const std::size_t ext_end = at + 2 + be16(h, at);
  check(ext_end == h.size(), "the extension block closes on the end of the hello");
  at += 2;

  bool saw_tp = false, saw_alpn = false, saw_sni = false;
  while (at < ext_end) {
    const unsigned type = be16(h, at);
    const std::size_t len = be16(h, at + 2);
    at += 4;
    if (type == 0x0000) saw_sni = true;
    if (type == 0x0010) saw_alpn = true;
    if (type == 0x0039) {
      saw_tp = true;
      // The bug this exists for: a parameter whose declared length disagrees
      // with the varint it precedes. The server answers a missing_extension
      // alert, and the run measures a rejection instead of a hold.
      std::size_t p = at, end = at + len;
      while (p < end) {
        get_varint(h, p);                            // id
        const std::uint64_t vlen = get_varint(h, p);
        check(p + vlen <= end, "a transport parameter stays inside the extension");
        p += vlen;
      }
      check(p == end, "every transport parameter length matches its value");
    }
    if (type == 0x002b) {
      check(static_cast<unsigned char>(h[at]) == 2 && be16(h, at + 1) == 0x0304,
            "supported_versions offers TLS 1.3 and nothing else");
    }
    at += len;
  }
  check(saw_tp, "quic_transport_parameters is present, without which QUIC refuses");
  check(saw_alpn, "ALPN is offered");
  check(saw_sni, "SNI is offered for a named host");

  slowhttp::quic::HelloOptions bare;
  bare.scid = std::string(8, 'S');
  check(slowhttp::quic::client_hello(bare).find("example.test") == std::string::npos,
        "no SNI when the caller supplies no host");
}

static void test_initial_packet_shape() {
  const std::string dcid(8, 'D'), scid(8, 'S');
  const Keys k = slowhttp::quic::initial_keys(dcid, false);
  const std::string pkt =
      slowhttp::quic::initial_packet(dcid, scid, k, 0, 0, std::string(100, 'x'));

  check(pkt.size() >= 1200,
        "a datagram carrying an Initial reaches the 1200-byte floor (RFC 9000 14.1)");
  const unsigned char b0 = static_cast<unsigned char>(pkt[0]);
  // The low four bits are masked by header protection; the top four are not.
  check((b0 & 0xf0) == 0xc0, "long header, Initial type");
  check(be16(pkt, 1) == 0 && be16(pkt, 3) == 1, "version 1");
  check(static_cast<unsigned char>(pkt[5]) == dcid.size(), "the DCID length is declared");
  check(pkt.compare(6, dcid.size(), dcid) == 0, "and the DCID itself is carried");

  // The declared length must cover the packet number and everything after it,
  // or the server stops reading in the wrong place.
  std::size_t at = 6 + dcid.size();
  at += 1 + scid.size();
  get_varint(pkt, at);                                // token length
  const std::uint64_t declared = get_varint(pkt, at);
  check(at + declared == pkt.size(),
        "the length field accounts for exactly the rest of the packet");
}

static void test_every_dribble_costs_a_full_datagram() {
  // The floor is the economics of this attack. A ClientHello is a couple of
  // hundred bytes and a dribbled fragment is a handful, but both ride in a
  // 1200-byte datagram, so sending less does not cost less. Only a payload that
  // exceeds the floor makes a larger packet.
  const std::string dcid(8, 'D'), scid(8, 'S');
  const Keys k = slowhttp::quic::initial_keys(dcid, false);
  const std::string tiny =
      slowhttp::quic::initial_packet(dcid, scid, k, 0, 0, std::string(8, 'x'));
  const std::string typical =
      slowhttp::quic::initial_packet(dcid, scid, k, 0, 0, std::string(1000, 'x'));
  const std::string over =
      slowhttp::quic::initial_packet(dcid, scid, k, 0, 0, std::string(1400, 'x'));
  check(tiny.size() == 1200, "an 8-byte fragment still costs a 1200-byte datagram");
  check(typical.size() == 1200, "so does a 1000-byte one");
  check(over.size() > 1200, "only a payload past the floor grows the packet");
}

static void test_oversized_connection_ids_are_refused() {
  // The header writes the connection ID length into a single byte, so a long
  // one used to wrap: 300 bytes declared itself as 44 and the packet went out
  // describing a length it did not have. RFC 9000 17.2 caps a connection ID at
  // 20 bytes, which is the boundary worth holding.
  const Keys k = slowhttp::quic::initial_keys(std::string(8, 'D'), false);
  const std::string scid(8, 'S'), data(50, 'x');
  check(!slowhttp::quic::initial_packet(std::string(20, 'D'), scid, k, 0, 0, data).empty(),
        "a 20-byte connection ID is legal and still builds");
  check(slowhttp::quic::initial_packet(std::string(21, 'D'), scid, k, 0, 0, data).empty(),
        "21 bytes is over the RFC limit and is refused");
  check(slowhttp::quic::initial_packet(std::string(300, 'D'), scid, k, 0, 0, data).empty(),
        "and a length that would wrap the byte is refused rather than truncated");
  check(slowhttp::quic::initial_packet(std::string(8, 'D'), std::string(21, 'S'), k, 0, 0, data).empty(),
        "the source connection ID is held to the same limit");
}

static void test_a_tiny_floor_still_builds_a_samplable_packet() {
  // min_datagram is a parameter, and header protection needs 19 bytes past the
  // packet number to sample. Lowering the floor must not produce a packet too
  // short to protect.
  const Keys k = slowhttp::quic::initial_keys(std::string(8, 'D'), false);
  for (std::size_t floor : {std::size_t(0), std::size_t(1), std::size_t(32)}) {
    const std::string p = slowhttp::quic::initial_packet(
        std::string(8, 'D'), std::string(8, 'S'), k, 0, 0, std::string(), floor);
    check(!p.empty(), "a packet is still produced with a tiny floor");
    // 1 flags + 4 version + 1+8 dcid + 1+8 scid + 1 token + len + 1 pn
    check(p.size() >= 19, "and it is long enough for the sample to come from");
  }
}

static void test_classify_reads_the_long_header() {
  auto pkt = [](unsigned b0, unsigned ver) {
    std::string s;
    s.push_back(static_cast<char>(b0));
    for (int i = 3; i >= 0; --i) s.push_back(static_cast<char>((ver >> (8 * i)) & 0xff));
    s.append(20, '\0');
    return s;
  };
  using slowhttp::quic::classify;
  check(classify(nullptr, 0) == Reply::None, "nothing is nothing");
  check(classify(pkt(0xc0, 1).data(), 25) == Reply::Initial, "Initial");
  check(classify(pkt(0xe0, 1).data(), 25) == Reply::Handshake, "Handshake");
  // A server never sends 0-RTT, but the type bits are three wide and the
  // unused value must not fall through onto a neighbour's meaning.
  check(classify(pkt(0xd0, 1).data(), 25) == Reply::ZeroRtt, "0-RTT");
  check(classify(pkt(0xf0, 1).data(), 25) == Reply::Retry, "Retry");
  check(classify(pkt(0xc0, 0).data(), 25) == Reply::VersionNegotiation,
        "version zero is a Version Negotiation whatever the type bits say");
  const char short_hdr[] = {0x40, 0x01, 0x02};
  check(classify(short_hdr, sizeof(short_hdr)) == Reply::Short, "1-RTT");
  // Retry and Handshake are the two that decide the verdict, so they must never
  // collapse into each other.
  check(classify(pkt(0xf0, 1).data(), 25) != classify(pkt(0xe0, 1).data(), 25),
        "Retry and Handshake stay distinct");
}

int main() {
  if (!slowhttp::quic::available()) {
    std::printf("quic: skipped, this build has no crypto backend\n");
    return 0;
  }
  test_rfc9001_appendix_a_keys();
  test_varint_boundaries();
  test_hello_is_quic_shaped();
  test_initial_packet_shape();
  test_every_dribble_costs_a_full_datagram();
  test_oversized_connection_ids_are_refused();
  test_a_tiny_floor_still_builds_a_samplable_packet();
  test_classify_reads_the_long_header();
  if (failures == 0) {
    std::printf("quic: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "quic: %d check(s) failed\n", failures);
  return 1;
}
