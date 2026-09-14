// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_QUIC_HPP_
#define SLOWHTTP_QUIC_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

namespace slowhttp {
namespace quic {

// Just enough QUIC to send an Initial packet and read the shape of the answer.
//
// This is not a QUIC stack and is not meant to become one. It exists because
// Initial packets are the one part of QUIC that needs no handshake state:
// their protection keys come from a published salt and the Destination
// Connection ID (RFC 9001 5.2), so a client can build one with nothing but
// HKDF and AES. Everything past the Initial -- Handshake keys, loss recovery,
// congestion control, streams -- requires the TLS key schedule and is
// deliberately absent. An attack that stops inside the handshake never needs
// any of it.
//
// Verified by interoperating rather than by inspection: packets built here are
// accepted by nginx 1.31 and quic-go 0.62, both of which answer them.

// Whether this build has the crypto to construct a packet. False when built
// with -DSLOWHTTP_TLS=OFF, in which case every function below is a no-op.
bool available();

// RFC 9000 16: variable-length integer, two-bit length prefix.
void put_varint(std::string& out, std::uint64_t v);
std::size_t varint_size(std::uint64_t v);

// Packet protection keys for one connection. `ok` is false if the build has no
// crypto backend.
struct Keys {
  std::string key;  // AEAD key, 16 bytes for AES-128-GCM
  std::string iv;   // 12 bytes, XORed with the packet number to make the nonce
  std::string hp;   // header protection key, 16 bytes
  bool ok = false;
};

// Initial keys for `dcid`. The server's keys come from the same connection ID,
// which is what lets a client read the reply without any handshake state.
Keys initial_keys(const std::string& dcid, bool server);

struct HelloOptions {
  std::string host;         // SNI, or empty for a literal address (RFC 6066 3)
  std::string scid;         // echoed in initial_source_connection_id
  std::string alpn = "h3";
};

// A TLS 1.3 ClientHello shaped for QUIC: no legacy session id (RFC 9001 8.4),
// TLS 1.3 only, and carrying the transport parameters without which a QUIC
// server rejects the handshake.
std::string client_hello(const HelloOptions& opt);

// A protected Initial packet carrying CRYPTO data at `offset`, padded out to
// `min_datagram` bytes. RFC 9000 14.1 requires a datagram containing an Initial
// to be at least 1200 bytes, so that padding is mandatory rather than a choice:
// it is the floor on what this attack costs to send.
std::string initial_packet(const std::string& dcid, const std::string& scid,
                           const Keys& keys, std::uint64_t packet_number,
                           std::uint64_t crypto_offset,
                           const std::string& crypto_data,
                           std::size_t min_datagram = 1200);

// What a datagram from the server is, read from the long header alone. No
// decryption: the packet type is unprotected, and it already separates the
// cases that matter. A Handshake packet cannot exist unless the server
// produced a ServerHello, so its presence is proof the expensive half of the
// handshake ran.
enum class Reply {
  None,
  Initial,             // taken, but nothing produced yet
  ZeroRtt,
  Handshake,           // the server ran the key exchange and signed
  Retry,               // address validation: no connection state was created
  VersionNegotiation,
  Short,               // 1-RTT, which should not happen here
  Malformed
};
Reply classify(const char* data, std::size_t len);

}  // namespace quic
}  // namespace slowhttp

#endif  // SLOWHTTP_QUIC_HPP_
