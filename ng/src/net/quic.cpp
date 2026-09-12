// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Compiled unconditionally; without SLOWHTTP_HAVE_TLS every function that needs
// crypto returns empty and available() says so, the same arrangement tls.cpp
// uses.
#include "slowhttp/quic.hpp"

#include <cstring>

#ifdef SLOWHTTP_HAVE_TLS
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

namespace slowhttp {
namespace quic {
namespace {

void u8(std::string& o, unsigned v) { o.push_back(static_cast<char>(v & 0xff)); }

#ifdef SLOWHTTP_HAVE_TLS

void u16(std::string& o, unsigned v) { u8(o, v >> 8); u8(o, v); }
void u24(std::string& o, unsigned v) { u8(o, v >> 16); u8(o, v >> 8); u8(o, v); }

// RFC 9001 5.2: the version-1 salt. Public and constant -- this is the whole
// reason an Initial packet needs no negotiated state.
const unsigned char kInitialSalt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

std::string hmac_sha256(const std::string& key, const std::string& data) {
  unsigned char out[32];
  unsigned len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(), out,
       &len);
  return std::string(reinterpret_cast<char*>(out), len);
}

std::string hkdf_expand(const std::string& prk, const std::string& info,
                        std::size_t len) {
  std::string out, t;
  for (unsigned char c = 1; out.size() < len; ++c)
    out += (t = hmac_sha256(prk, t + info + std::string(1, static_cast<char>(c))));
  out.resize(len);
  return out;
}

// RFC 8446 7.1 HkdfLabel, with the "tls13 " prefix QUIC also uses.
std::string expand_label(const std::string& secret, const std::string& label,
                         std::size_t len) {
  std::string info;
  u16(info, static_cast<unsigned>(len));
  const std::string full = "tls13 " + label;
  u8(info, static_cast<unsigned>(full.size()));
  info += full;
  u8(info, 0);
  return hkdf_expand(secret, info, len);
}

std::string random_bytes(std::size_t n) {
  std::string s(n, '\0');
  RAND_bytes(reinterpret_cast<unsigned char*>(&s[0]), static_cast<int>(n));
  return s;
}

void extension(std::string& o, unsigned type, const std::string& body) {
  u16(o, type);
  u16(o, static_cast<unsigned>(body.size()));
  o += body;
}

#endif  // SLOWHTTP_HAVE_TLS

}  // namespace

bool available() {
#ifdef SLOWHTTP_HAVE_TLS
  return true;
#else
  return false;
#endif
}

void put_varint(std::string& out, std::uint64_t v) {
  if (v < 64) {
    u8(out, static_cast<unsigned>(v));
  } else if (v < 16384) {
    u8(out, 0x40 | static_cast<unsigned>((v >> 8) & 0x3f));
    u8(out, static_cast<unsigned>(v));
  } else if (v < 1073741824ULL) {
    u8(out, 0x80 | static_cast<unsigned>((v >> 24) & 0x3f));
    u8(out, static_cast<unsigned>(v >> 16));
    u8(out, static_cast<unsigned>(v >> 8));
    u8(out, static_cast<unsigned>(v));
  } else {
    u8(out, 0xc0 | static_cast<unsigned>((v >> 56) & 0x3f));
    for (int s = 48; s >= 0; s -= 8) u8(out, static_cast<unsigned>(v >> s));
  }
}

std::size_t varint_size(std::uint64_t v) {
  if (v < 64) return 1;
  if (v < 16384) return 2;
  if (v < 1073741824ULL) return 4;
  return 8;
}

Keys initial_keys(const std::string& dcid, bool server) {
  Keys k;
#ifdef SLOWHTTP_HAVE_TLS
  const std::string initial = hmac_sha256(
      std::string(reinterpret_cast<const char*>(kInitialSalt), 20), dcid);
  const std::string side =
      expand_label(initial, server ? "server in" : "client in", 32);
  k.key = expand_label(side, "quic key", 16);
  k.iv = expand_label(side, "quic iv", 12);
  k.hp = expand_label(side, "quic hp", 16);
  k.ok = true;
#else
  (void)dcid;
  (void)server;
#endif
  return k;
}

std::string client_hello(const HelloOptions& opt) {
  std::string b;
#ifdef SLOWHTTP_HAVE_TLS
  u16(b, 0x0303);            // legacy_version, fixed at TLS 1.2 (RFC 8446 4.1.2)
  b += random_bytes(32);
  // RFC 9001 8.4: QUIC does not use TLS's middlebox compatibility mode, and a
  // server MUST reject a non-empty legacy_session_id. This is the one place
  // the QUIC hello must differ from the TCP one.
  u8(b, 0);
  u16(b, 6);                 // TLS 1.3 suites only; QUIC forbids earlier versions
  u16(b, 0x1301);
  u16(b, 0x1302);
  u16(b, 0x1303);
  u8(b, 1);
  u8(b, 0);

  std::string e;
  if (!opt.host.empty()) {
    std::string sni;
    u8(sni, 0);
    u16(sni, static_cast<unsigned>(opt.host.size()));
    sni += opt.host;
    std::string list;
    u16(list, static_cast<unsigned>(sni.size()));
    list += sni;
    extension(e, 0x0000, list);
  }
  {  // supported_groups: x25519
    std::string g;
    u16(g, 2);
    u16(g, 0x001d);
    extension(e, 0x000a, g);
  }
  {
    const unsigned algs[] = {0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0603};
    std::string s;
    u16(s, 12);
    for (unsigned v : algs) u16(s, v);
    extension(e, 0x000d, s);
  }
  if (!opt.alpn.empty()) {
    std::string a;
    u16(a, static_cast<unsigned>(opt.alpn.size() + 1));
    u8(a, static_cast<unsigned>(opt.alpn.size()));
    a += opt.alpn;
    extension(e, 0x0010, a);
  }
  {  // supported_versions: TLS 1.3 only
    std::string v;
    u8(v, 2);
    u16(v, 0x0304);
    extension(e, 0x002b, v);
  }
  {
    std::string m;
    u8(m, 1);
    u8(m, 1);
    extension(e, 0x002d, m);
  }
  {  // key_share: one x25519 share. Never used -- the handshake does not get
     // far enough to derive anything from it.
    std::string k, en;
    u16(en, 0x001d);
    u16(en, 32);
    en += random_bytes(32);
    u16(k, static_cast<unsigned>(en.size()));
    k += en;
    extension(e, 0x0033, k);
  }
  {  // quic_transport_parameters (RFC 9001 8.2). Without it the server answers
     // a missing_extension alert, which measures the rejection and not a hold.
     // Each parameter is varint id, varint length, value -- and the length has
     // to match what the value actually encodes to.
    std::string tp;
    auto param = [&tp](std::uint64_t id, std::uint64_t value) {
      std::string v;
      put_varint(v, value);
      put_varint(tp, id);
      put_varint(tp, v.size());
      tp += v;
    };
    param(0x01, 30000);     // max_idle_timeout
    param(0x04, 1048576);   // initial_max_data
    param(0x05, 262144);    // initial_max_stream_data_bidi_local
    param(0x08, 100);       // initial_max_streams_bidi
    param(0x09, 100);       // initial_max_streams_uni
    put_varint(tp, 0x0f);   // initial_source_connection_id, required of a client
    put_varint(tp, opt.scid.size());
    tp += opt.scid;
    extension(e, 0x0039, tp);
  }
  u16(b, static_cast<unsigned>(e.size()));
  b += e;

  std::string h;
  u8(h, 0x01);  // handshake type: client_hello
  u24(h, static_cast<unsigned>(b.size()));
  h += b;
  return h;
#else
  (void)opt;
  return b;
#endif
}

std::string initial_packet(const std::string& dcid, const std::string& scid,
                           const Keys& keys, std::uint64_t packet_number,
                           std::uint64_t crypto_offset,
                           const std::string& crypto_data,
                           std::size_t min_datagram) {
#ifdef SLOWHTTP_HAVE_TLS
  if (!keys.ok) return std::string();

  std::string payload;
  put_varint(payload, 0x06);  // CRYPTO frame
  put_varint(payload, crypto_offset);
  put_varint(payload, crypto_data.size());
  payload += crypto_data;

  // Packet numbers are sent in one byte here. The attack never gets far enough
  // to need a wider space, and a fixed width keeps the header size known before
  // the length field has to be written.
  const unsigned pn = static_cast<unsigned>(packet_number & 0xff);

  std::string hdr;
  u8(hdr, 0xc0);  // long header, Initial, 1-byte packet number
  u8(hdr, 0x00);
  u8(hdr, 0x00);
  u8(hdr, 0x00);
  u8(hdr, 0x01);  // version 1
  u8(hdr, static_cast<unsigned>(dcid.size()));
  hdr += dcid;
  u8(hdr, static_cast<unsigned>(scid.size()));
  hdr += scid;
  put_varint(hdr, 0);  // token length: none, this is not a response to a Retry

  // PADDING frames to the datagram floor. The length varint is two bytes for
  // everything in range here, which the floor guarantees.
  const std::size_t fixed = hdr.size() + 2 + 1 + 16;
  if (fixed + payload.size() < min_datagram)
    payload.append(min_datagram - fixed - payload.size(), '\0');
  put_varint(hdr, payload.size() + 1 + 16);
  u8(hdr, pn);
  const std::size_t pn_off = hdr.size() - 1;

  std::string nonce = keys.iv;
  for (int i = 0; i < 8; ++i)
    nonce[11 - i] = static_cast<char>(
        nonce[11 - i] ^ static_cast<unsigned char>((packet_number >> (8 * i)) & 0xff));

  std::string out(payload.size() + 16, '\0');
  int outl = 0, finl = 0;
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  if (!c) return std::string();
  EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
  EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
  EVP_EncryptInit_ex(c, nullptr, nullptr,
                     reinterpret_cast<const unsigned char*>(keys.key.data()),
                     reinterpret_cast<const unsigned char*>(nonce.data()));
  // The header is authenticated, not encrypted.
  EVP_EncryptUpdate(c, nullptr, &outl,
                    reinterpret_cast<const unsigned char*>(hdr.data()),
                    static_cast<int>(hdr.size()));
  EVP_EncryptUpdate(c, reinterpret_cast<unsigned char*>(&out[0]), &outl,
                    reinterpret_cast<const unsigned char*>(payload.data()),
                    static_cast<int>(payload.size()));
  EVP_EncryptFinal_ex(c, reinterpret_cast<unsigned char*>(&out[0]) + outl, &finl);
  unsigned char tag[16];
  EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag);
  EVP_CIPHER_CTX_free(c);
  out.resize(static_cast<std::size_t>(outl + finl));
  out += std::string(reinterpret_cast<char*>(tag), 16);

  // Header protection (RFC 9001 5.4): a mask from AES-ECB over a ciphertext
  // sample taken four bytes past the start of the packet number.
  const unsigned char* sample =
      reinterpret_cast<const unsigned char*>(out.data()) + 3;
  unsigned char mask[32];
  int ml = 0;
  EVP_CIPHER_CTX* h = EVP_CIPHER_CTX_new();
  if (!h) return std::string();
  EVP_EncryptInit_ex(h, EVP_aes_128_ecb(), nullptr,
                     reinterpret_cast<const unsigned char*>(keys.hp.data()),
                     nullptr);
  EVP_CIPHER_CTX_set_padding(h, 0);
  EVP_EncryptUpdate(h, mask, &ml, sample, 16);
  EVP_CIPHER_CTX_free(h);

  std::string pkt = hdr + out;
  pkt[0] = static_cast<char>(pkt[0] ^ (mask[0] & 0x0f));
  pkt[pn_off] = static_cast<char>(pkt[pn_off] ^ mask[1]);
  return pkt;
#else
  (void)dcid; (void)scid; (void)keys; (void)packet_number;
  (void)crypto_offset; (void)crypto_data; (void)min_datagram;
  return std::string();
#endif
}

Reply classify(const char* data, std::size_t len) {
  if (data == nullptr || len == 0) return Reply::None;
  const unsigned char b0 = static_cast<unsigned char>(data[0]);
  if ((b0 & 0x80) == 0) return Reply::Short;
  if (len < 5) return Reply::Malformed;
  const unsigned version =
      (static_cast<unsigned char>(data[1]) << 24) |
      (static_cast<unsigned char>(data[2]) << 16) |
      (static_cast<unsigned char>(data[3]) << 8) |
      static_cast<unsigned char>(data[4]);
  if (version == 0) return Reply::VersionNegotiation;
  switch ((b0 & 0x30) >> 4) {
    case 0: return Reply::Initial;
    case 1: return Reply::ZeroRtt;
    case 2: return Reply::Handshake;
    default: return Reply::Retry;
  }
}

const char* reply_name(Reply r) {
  switch (r) {
    case Reply::None: return "nothing";
    case Reply::Initial: return "Initial";
    case Reply::ZeroRtt: return "0-RTT";
    case Reply::Handshake: return "Handshake";
    case Reply::Retry: return "Retry";
    case Reply::VersionNegotiation: return "Version Negotiation";
    case Reply::Short: return "1-RTT";
    case Reply::Malformed: return "malformed";
  }
  return "?";
}

}  // namespace quic
}  // namespace slowhttp
