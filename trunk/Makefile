VERSION		= 1 #current version
TARGET		= slowhttptest
DEFINES		= -DVERSION=$(VERSION)
CC=g++
CFLAGS=-c -Wall -O3 $(DEFINES)
LDFLAGS= -lssl
SOURCES=slowhttptestmain.cc slowhttptest.cc slowsocket.cc slowurl.cc slowlog.cc
OBJECTS=$(SOURCES:.cc=.o)

all: $(SOURCES) $(TARGET)
		
$(TARGET): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cc.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *o $(TARGET)

tags:
	@echo Generating tags...
	@rm -f tags
	@find -name "*.cc" | xargs ctags -a --extra=+q --fields=+i
	@find -name "*.h" | xargs ctags -a --extra=+q --fields=+i


