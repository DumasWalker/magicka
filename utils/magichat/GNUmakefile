CC=cc

DEPS = main.c

OBJ = main.o

OS = $(shell uname -s)
ifeq ($(OS), SunOS)
	EXTRA_LIBS = -lsocket
endif

ifeq ($(OS), Haiku)
	EXTRA_LIBS = -lnetwork
endif
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

JSMN = ../../deps/jsmn/libjsmn.a

all: magichat

$(JSMN):
	cd ../../deps/jsmn/ && $(MAKE)

magichat: $(OBJ) $(JSMN)
	$(CC) -o magichat -o $@ $^ $(LDFLAGS) $(EXTRA_LIBS)

.PHONY: clean

clean:
	rm -f $(OBJ) magichat
