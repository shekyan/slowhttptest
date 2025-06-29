FROM alpine:3.19 as builder

RUN apk add --no-cache build-base git openssl-dev autoconf automake
WORKDIR /build
COPY . /build
RUN ./configure && make


FROM alpine:3.19
RUN apk add --no-cache libstdc++
COPY --from=builder /build/src/slowhttptest /usr/local/bin/
ENTRYPOINT ["slowhttptest"]
