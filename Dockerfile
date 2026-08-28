# SPDX-License-Identifier: Apache-2.0
#
# Builds both tools during the transition to the C++ rewrite:
#
#   slowhttptest      the classic autotools build from src/
#   slowhttptest-ng   the rewrite from ng/, which will eventually replace it
#
# ENTRYPOINT is still the classic binary, so existing `docker run` invocations
# keep working unchanged. Reach the rewrite with:
#
#   docker run --rm --entrypoint slowhttptest-ng <image> -u http://target/ ...
#
# When ng takes over the name, the classic stage goes away and the ng binary is
# installed as `slowhttptest`.
FROM alpine:3.19 AS builder

RUN apk add --no-cache build-base git openssl-dev autoconf automake cmake
WORKDIR /build
COPY . /build

# Classic tool.
RUN ./configure && make

# Rewrite. Installed into a staging root so only the artifacts are copied on.
RUN cmake -S ng -B ng/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build ng/build -j "$(nproc)" \
    && DESTDIR=/staging cmake --install ng/build --prefix /usr/local


FROM alpine:3.19
# libstdc++ for both binaries, and the OpenSSL runtime libraries they link
# against for https support. The libraries were previously missing here, which
# only stayed invisible for as long as nobody used an https target.
RUN apk add --no-cache libstdc++ libssl3 libcrypto3
COPY --from=builder /build/src/slowhttptest /usr/local/bin/
COPY --from=builder /staging/usr/local/ /usr/local/
ENTRYPOINT ["slowhttptest"]
