
PIDGIN_TREE_TOP ?= ../pidgin-2.10.11
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw-4.7.2/bin/gcc
MAKENSIS ?= makensis

PKG_CONFIG ?= pkg-config

CFLAGS	?= -O2 -g -pipe
LDFLAGS ?= 

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  #only defined on 64-bit windows
  PROGFILES32 = ${ProgramFiles(x86)}
  ifndef PROGFILES32
    PROGFILES32 = $(PROGRAMFILES)
  endif
  ICYQUE_TARGET = libicyque.dll
  ICYQUE_DEST = "$(PROGFILES32)/Pidgin/plugins"
  ICYQUE_ICONS_DEST = "$(PROGFILES32)/Pidgin/pixmaps/pidgin/protocols"
  MAKENSIS = "$(PROGFILES32)/NSIS/makensis.exe"
else

  UNAME_S := $(shell uname -s)

  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    INCLUDES = -I/opt/local/include -lz $(OS)

    CC = gcc
  else
    INCLUDES = 
    CC ?= gcc
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      ICYQUE_TARGET = FAILNOPURPLE
      ICYQUE_DEST =
	  ICYQUE_ICONS_DEST =
    else
      ICYQUE_TARGET = libicyque.so
      ICYQUE_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
	  ICYQUE_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
    endif
  else
    ICYQUE_TARGET = libicyque3.so
    ICYQUE_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
	ICYQUE_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
  endif
endif

WIN32_CFLAGS = -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -I$(WIN32_DEV_TOP)/json-glib-0.14/include/json-glib-1.0 -DENABLE_NLS -DPACKAGE_VERSION='"$(PLUGIN_VERSION)"' -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(WIN32_DEV_TOP)/json-glib-0.14/lib -lpurple -lintl -lglib-2.0 -lgobject-2.0 -ljson-glib-1.0 -g -ggdb -static-libgcc -lz
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

C_FILES := libicyque.c
PURPLE_COMPAT_FILES := purple2compat/http.c purple2compat/purple-socket.c
PURPLE_C_FILES := libicyque.c $(C_FILES)
TEST_C_FILES := icyque_test.c $(C_FILES)



.PHONY:	all install FAILNOPURPLE clean

all: $(ICYQUE_TARGET)

libicyque.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 zlib --libs --cflags` -ldl $(INCLUDES) -Ipurple2compat -g -ggdb

libicyque3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 zlib --libs --cflags` -ldl $(INCLUDES) -g -ggdb

libicyque.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libicyque3.dll: $(PURPLE_C_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

icyque-test.exe: $(TEST_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -o $@ -DDEBUG $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

install: $(ICYQUE_TARGET)
	mkdir -p $(ICYQUE_DEST)
	install -p $(ICYQUE_TARGET) $(ICYQUE_DEST)

FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(ICYQUE_TARGET)


installer: purple-icyque.nsi libicyque.dll
	$(MAKENSIS) purple-icyque.nsi
