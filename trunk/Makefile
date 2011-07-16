VERSION					= 1 #current version
BIN_DIR					= bin/
TARGET					= $(BIN_DIR)slowhttptest
DEFINES					= -DVERSION=$(VERSION)
SOURCES					= slowhttptestmain.cc slowhttptest.cc slowsocket.cc slowurl.cc slowlog.cc
OBJECT_FILES		= $(SOURCES:.cc=.o)
OBJECTS					= $(addprefix $(BIN_DIR), $(OBJECT_FILES))
CHK_DIR_EXISTS	= test -d
MOVE          	= mv -f
MKDIR         	= mkdir -p
DEL_FILE      	= rm -f
INSTALL_PROGRAM = install -m 755 -p
CC							= g++
CFLAGS					= -c -g -Wall -O3 $(DEFINES)
LDFLAGS					= -lssl

all: create_bin $(SOURCES) $(TARGET) 
		
$(TARGET): $(OBJECT_FILES)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cc.o:
	$(CC) $(CFLAGS) $< -o $(BIN_DIR)$@

clean:
	@echo Removing binary files...
	@$(DEL_FILE) $(OBJECTS) $(TARGET)

tags:
	@echo Generating tags...
	@rm -f tags
	@find -name "*.cc" | xargs ctags -a --extra=+q --fields=+i
	@find -name "*.h" | xargs ctags -a --extra=+q --fields=+i

create_bin:
	@$(CHK_DIR_EXISTS) $(BIN_DIR) || $(MKDIR) $(BIN_DIR)
	@$(DEL_FILE) $(OBJECTS) $(TARGET)
