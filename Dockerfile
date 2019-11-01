FROM alpine:3.9

RUN apk add --no-cache build-base git openssl-dev
RUN mkdir /slowhttptest
WORKDIR /slowhttptest
COPY . /slowhttptest
RUN touch ./*
RUN ./configure --prefix=/usr/local
RUN make && make install
ENTRYPOINT ["slowhttptest"]
