all: slowhttptest

slowhttptest: slowhttptestmain.o slowhttptest.o slowsocket.o slowurl.o slowlog.o
	g++ -g -lssl  slowhttptest.o slowhttptestmain.o slowsocket.o slowurl.o slowlog.o -o slowhttptest

slowhttptestmain.o: slowhttptestmain.cc
	g++ -g -c slowhttptestmain.cc

slowhttptest.o: slowhttptest.cc
	g++ -g -c slowhttptest.cc

slowsocket.o: slowsocket.cc
	g++ -g -c slowsocket.cc

slowurl.o: slowurl.cc
	g++ -g -c slowurl.cc

slowlog.o: slowlog.cc
	g++ -g -c slowlog.cc

clean:
	rm -rf *o slowhttptest

