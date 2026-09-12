#!/usr/bin/env python3
"""A UDP responder that plays the three answers a QUIC server can give.

Not a QUIC implementation. It reads the long header of whatever arrives to
confirm the client really sent a version-1 Initial, and then replies with the
packet type the test asked for. That is enough to pin down how the tool
classifies each answer, which is the part of --slow-quic worth testing
deterministically.

Interoperation with real stacks is verified by hand against nginx and quic-go;
this exists so the classification cannot regress unnoticed.

  --retry    reply with a Retry, as a server doing address validation does
  --ack      reply with an Initial, as a server that took the packet and is
             holding it does
  --flight   reply with an Initial and then a Handshake packet, as a server
             that ran the key exchange does
  --silent   read and never answer
"""
import argparse
import socket
import sys


def long_header(type_bits, version=1):
    b0 = 0xC0 | (type_bits << 4)
    return bytes([b0]) + version.to_bytes(4, "big") + b"\x00" * 40


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--retry", action="store_true")
    mode.add_argument("--ack", action="store_true")
    mode.add_argument("--flight", action="store_true")
    mode.add_argument("--silent", action="store_true")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", args.port))
    print("mock quic on udp/%d" % args.port, flush=True)

    seen = 0
    while True:
        try:
            data, peer = s.recvfrom(4096)
        except OSError:
            break
        # Only answer something that is actually a QUIC v1 Initial, so a test
        # that sends nonsense cannot pass by accident.
        if len(data) < 5 or not (data[0] & 0x80):
            continue
        if int.from_bytes(data[1:5], "big") != 1:
            continue
        if (data[0] & 0x30) >> 4 != 0:
            continue
        seen += 1
        if args.silent:
            continue
        if args.retry:
            s.sendto(long_header(3), peer)
        elif args.ack:
            s.sendto(long_header(0), peer)
        elif args.flight:
            s.sendto(long_header(0), peer)
            s.sendto(long_header(2), peer)


if __name__ == "__main__":
    sys.exit(main())
