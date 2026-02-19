OS := $(shell uname -s)

ifeq ($(OS), FreeBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib
endif
ifeq ($(OS), NetBSD)
  CC=cc
  CFLAGS=-I/usr/pkg/include
  LDFLAGS=-L/usr/pkg/lib
endif
ifeq ($(OS), Linux)
  CC=gcc
  CFLAGS=
  LDFLAGS=
endif
ifeq ($(OS), Darwin)
  CC=cc
  CFLAGS=
  LDFLAGS=
endif


CC=cc
CFLAGS=-I/usr/local/include
DEPS = main.c

OBJ = main.o load_ini.o systemconfig.o systempaths.o mailconfs.o mailareas.o filedirs.o filesubs.o textfiles.o archivers.o ../../inih/ini.o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -I../../deps/cdk-5.0-20161210/include/

ccenter: $(OBJ)
	$(CC) -o ccenter -o $@ $^ ../../deps/cdk-5.0-20161210/libcdk.a $(CFLAGS) $(LDFLAGS) -lncurses

.PHONY: clean

clean:
	rm -f $(OBJ) ccenter
