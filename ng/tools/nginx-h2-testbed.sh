#!/bin/sh
# Set up a local nginx HTTP/2 testbed under /tmp/ng-nginx.
#
#   tools/nginx-h2-testbed.sh setup   # lay out the prefix, cert and big file
#   tools/nginx-h2-testbed.sh start
#   tools/nginx-h2-testbed.sh stop
#   tools/nginx-h2-testbed.sh check   # is it actually speaking HTTP/2?
#
# Nothing here touches the system nginx configuration: everything lives in a
# prefix under /tmp, so `nginx -p` runs it without root and removing the
# directory undoes it entirely.

set -e
PREFIX=/tmp/ng-nginx
CONF=$(cd "$(dirname "$0")" && pwd)/nginx-h2-testbed.conf

case "${1:-}" in
setup)
    command -v nginx >/dev/null || { echo "nginx not found: brew install nginx"; exit 1; }
    ver=$(nginx -v 2>&1 | sed 's/.*nginx\///')
    echo "nginx $ver"
    case "$ver" in
        1.1*|1.2[0-4]*)
            echo "WARNING: 'http2 on;' needs nginx >= 1.25.1."
            echo "         On older builds h2c will not work and only the TLS"
            echo "         listener will speak HTTP/2." ;;
    esac

    mkdir -p "$PREFIX/logs" "$PREFIX/html"
    cp "$CONF" "$PREFIX/nginx.conf"

    # A body big enough that it cannot sit in socket buffers. Slow read is only
    # interesting when the server has to hold something.
    if [ ! -f "$PREFIX/html/big.bin" ]; then
        echo "making a 64 MB response body..."
        dd if=/dev/zero of="$PREFIX/html/big.bin" bs=1m count=64 2>/dev/null
    fi

    # Self-signed, for the ALPN listener only. Nothing verifies it and the tool
    # does not check certificates by default.
    if [ ! -f "$PREFIX/cert.pem" ]; then
        echo "making a self-signed certificate..."
        openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
            -subj "/CN=localhost" \
            -keyout "$PREFIX/key.pem" -out "$PREFIX/cert.pem" 2>/dev/null
    fi
    echo "ready: $PREFIX"
    ;;
start)
    nginx -p "$PREFIX" -c nginx.conf
    sleep 0.5
    echo "started; error log: $PREFIX/logs/error.log"
    ;;
stop)
    nginx -p "$PREFIX" -c nginx.conf -s quit 2>/dev/null || true
    echo "stopped"
    ;;
check)
    # curl proves the server speaks h2c before any conclusion is drawn from the
    # tool's own behaviour. Without this a framing bug and a server that never
    # had HTTP/2 enabled look identical.
    if curl --http2-prior-knowledge -s -o /dev/null -w "h2c: HTTP/%{http_version} %{http_code}\n" \
        http://127.0.0.1:8080/ 2>/dev/null; then :; else
        echo "h2c: curl could not speak HTTP/2 to :8080"
    fi
    curl -k --http2 -s -o /dev/null -w "tls: HTTP/%{http_version} %{http_code}\n" \
        https://127.0.0.1:8443/ 2>/dev/null || echo "tls: no answer on :8443"
    ;;
*)
    sed -n '2,12p' "$0"
    exit 2
    ;;
esac
