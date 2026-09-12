// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_SLOW_QUIC_HPP_
#define SLOWHTTP_ATTACKS_SLOW_QUIC_HPP_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"
#include "slowhttp/quic.hpp"

namespace slowhttp {

// A QUIC handshake that is opened and then not finished.
//
// The other modes hold a TCP connection, which costs the client a socket for as
// long as it costs the server one. QUIC breaks that symmetry: the server
// creates connection state on the first Initial packet it accepts, before the
// client has proved anything, and it keeps that state whether or not the client
// ever speaks again. Measured against nginx 1.31, one 1200-byte datagram bought
// over 76 seconds of server-side state; against quic-go 0.62, exactly 5.0 -- the
// difference is a handshake timeout that one of them has and the other does not.
//
// Two ways to leave the handshake unfinished, because they cost the server
// different things:
//
//   partial   The ClientHello arrives in fragments and the last one never
//             comes. The server parks a connection and buffers a CRYPTO stream
//             it cannot parse yet. No key exchange happens, so this is memory
//             and a connection-table slot and nothing else.
//
//   complete  The whole ClientHello arrives and then silence. The server runs
//             the key exchange, signs with its certificate, sends its entire
//             flight, and holds it for retransmission while it waits for a
//             Finished that never comes. That costs CPU and more memory, and
//             it is the only one of the two that produces an amplification
//             figure worth reading.
//
// What the run actually reports is which of three things the target did, read
// from the long header of whatever came back without decrypting any of it:
// a Retry means address validation is on and no state was created at all; a
// Handshake packet means the expensive half ran; an Initial and nothing more
// means the packet was taken and is being held.
//
// RFC 9000 14.1 requires any datagram carrying an Initial to be at least 1200
// bytes, so every packet this sends is 1200 bytes whether it carries the whole
// hello or eight bytes of it. Dribbling does not make the client's side
// cheaper; it is the server's willingness to wait that is being measured.
class SlowQuic : public Attack {
 public:
  enum class Hello { Partial, Complete };

  SlowQuic(const Config& cfg, Hello hello);

  const char* name() const override { return "slow QUIC handshake"; }

  // The reply is the measurement: Retry, Handshake or nothing each mean
  // something different about the target's defenses.
  bool wants_read_events() const override { return true; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;

  std::string summary() const override;

  long retried() const { return retried_; }
  long handshaked() const { return handshaked_; }
  long held() const { return held_; }
  long long bytes_in() const { return bytes_in_; }
  long long bytes_out() const { return bytes_out_; }
  std::size_t hello_size() const { return hello_size_; }
  // How far into its ClientHello a connection has got. Exposed because the
  // defining property of the partial mode -- that the last byte is never
  // delivered -- is otherwise unobservable: the packets are encrypted, and
  // the only other witness is a server that stays silent.
  std::size_t delivered(ConnId id) const {
    if (id < 0 || static_cast<std::size_t>(id) >= conns_.size()) return 0;
    return conns_[static_cast<std::size_t>(id)].sent;
  }

 private:
  // Per connection: its own identifiers, keys and position in the hello. A
  // connection ID is what makes two of these distinct to the server, so they
  // cannot be shared.
  struct Conn {
    std::string dcid;
    std::string scid;
    quic::Keys keys;
    std::string hello;
    std::size_t sent = 0;
    std::uint64_t packet_number = 0;
    // The strongest thing this connection has seen, because a server
    // typically ACKs in an Initial before its Handshake flight arrives.
    // Counting the first reply would file every completed handshake under
    // "merely held".
    int best_rank = 0;
  };

  std::string build_packet(Conn& c, std::size_t offset, std::size_t len);
  void reset(ConnId id);

  Hello hello_mode_;
  Millis interval_;
  std::size_t chunk_ = 0;
  std::string sni_;
  std::vector<Conn> conns_;
  std::size_t hello_size_ = 0;
  long started_ = 0;
  long retried_ = 0;
  long handshaked_ = 0;
  long held_ = 0;
  long long bytes_in_ = 0;
  long long bytes_out_ = 0;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_SLOW_QUIC_HPP_
