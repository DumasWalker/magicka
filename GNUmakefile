ifdef MUSL
	OS=linux-musl
else 
	OS=$(shell uname -s | tr '[A-Z]' '[a-z]' | sed 's/darwin/osx/')
endif

all:	magicka

.PHONY: magicka www clean cleanwww

magicka:
	cd src && $(MAKE) -f GNUmakefile.$(OS)

www:
	cd src && $(MAKE) -f GNUmakefile.$(OS) www

clean:
	cd src && $(MAKE) -f GNUmakefile.$(OS) clean

cleanwww:
	cd src && $(MAKE) -f GNUmakefile.$(OS) clean
