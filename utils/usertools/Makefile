OS := $(shell uname -s)

ifeq ($(OS), FreeBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib
endif
ifeq ($(OS), DragonFly)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib
endif
ifeq ($(OS), NetBSD)
  CC=cc
  CFLAGS=-I/usr/pkg/include
  LDFLAGS=-R/usr/pkg/lib -L/usr/pkg/lib
endif
ifeq ($(OS), OpenBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib
endif
ifeq ($(OS), Linux)
  CC=gcc
  CFLAGS=
  LDFLAGS=
endif
ifeq ($(OS), Darwin)
  CC=cc
  CFLAGS=-I/opt/local/include
  LDFLAGS=-L/opt/local/lib
endif
ifeq ($(OS), SunOS)
  CC=gcc-9
  CFLAGS=
  LDFLAGS=
endif


DEPS = userflag.c userdel.c reset_pass.c

FOBJ = userflag.o
DOBJ = userdel.o
ROBJ = reset_pass.o
SOBJ = usersec.o

all: userflag userdel reset_pass usersec

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

userflag: $(FOBJ)
	$(CC) -o userflag $^ $(CFLAGS) $(LDFLAGS) -lsqlite3

userdel: $(DOBJ)
	$(CC) -o userdel $^ $(CFLAGS) $(LDFLAGS) -lsqlite3

reset_pass: $(ROBJ)
	$(CC) -o reset_pass $^ $(CFLAGS) $(LDFLAGS) -lsqlite3 -lssl -lcrypto

usersec: $(SOBJ)
	$(CC) -o usersec $^ $(CFLAGS) $(LDFLAGS) -lsqlite3

.PHONY: clean

clean:
	rm -f $(FOBJ) $(DOBJ) $(ROBJ) $(SOBJ) usersec userflag userdel reset_pass
