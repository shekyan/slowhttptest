VERSION					= 1 #current version
BIN_DIR					= bin/
TARGET					= slowhttptest
DEFINES					= -DVERSION=$(VERSION)
SOURCES					= slowhttptestmain.cc slowhttptest.cc slowsocket.cc slowurl.cc slowlog.cc
OBJECTS					= $(SOURCES:.cc=.o)
CHK_DIR_EXISTS	= test -d
MOVE          	= mv -f
MKDIR         	= mkdir -p
DEL_FILE      	= rm -f
INSTALL_PROGRAM = install -m 755 -p
CC							= g++
CFLAGS					= -c -Wall -O3 $(DEFINES)
LDFLAGS					= -lssl

all: $(SOURCES) $(TARGET) install
		
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cc.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	@echo Removing binary files...
	@$(DEL_FILE) $(BIN_DIR)*.o $(BIN_DIR)$(TARGET)

tags:
	@echo Generating tags...
	@rm -f tags
	@find -name "*.cc" | xargs ctags -a --extra=+q --fields=+i
	@find -name "*.h" | xargs ctags -a --extra=+q --fields=+i

install:
	@echo Moving to bin...
	@$(CHK_DIR_EXISTS) $(BIN_DIR) || $(MKDIR) $(BIN_DIR)
	@$(DEL_FILE) $(BIN_DIR)*.o $(BIN_DIR)$(TARGET)
	@$(MOVE) *.o $(BIN_DIR)
	@$(INSTALL_PROGRAM) $(TARGET) $(BIN_DIR)$(TARGET)
	@$(DEL_FILE) $(TARGET)

