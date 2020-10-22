FROM alpine:3.9

RUN apk add --no-cache build-base git openssl-dev autoconf automake
WORKDIR /slowhttptest
COPY . /slowhttptest
RUN ./configure --prefix=/usr/local
RUN make && make install
ENTRYPOINT ["slowhttptest"]
