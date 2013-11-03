AUTOMAKE_OPTIONS = foreign

FLAGS=@CFLAGS@ -Wall -I/usr/local/include
LDFLAGS=@LDFLAGS@ -L/usr/local/lib -lssl

bin_PROGRAMS = slowhttptest
slowhttptest_SOURCES = slowhttptestmain.cc slowhttptest.cc slowsocket.cc slowstats.cc slowurl.cc slowlog.cc text-generator.cc range-generator.cc slowhttptest.h slowsocket.h slowstats.h slowurl.h slowlog.h text-generator.h range-generator.h
