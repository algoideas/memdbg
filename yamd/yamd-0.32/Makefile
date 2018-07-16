CC = gcc

# Add your values here if they are different from the defaults.

CXX =
PREFIX =

CFLAGS = -Wall -W -O2 -D__linux__ -D__i386__
CXXFLAGS = $(CFLAGS)
LDFLAGS=

ifeq ($(USING_DJGPP),1)
  ifeq ($(CXX),)
    CXX = gxx
  endif
  ifeq ($(PREFIX),)
    PREFIX=$(DJDIR)
  endif
else
  ifeq ($(CXX),)
    CXX = g++
  endif
  ifeq ($(PREFIX),)
    PREFIX=/usr/local
  endif
endif

# $(DJDIR) for DJGPP, or maybe /usr/local on Unix

BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib

VERSION=0.32

FINAL_CFLAGS = $(CFLAGS) -DYAMD_VERSION=\"$(VERSION)\"

STRIPCC=$(strip $(CC))
STRIPCXX=$(strip $(CXX))

BASECC=$(notdir $(STRIPCC))
BASECXX=$(notdir $(STRIPCXX))

ifdef DJDIR
USING_DJGPP=1
endif

ifeq ($(USING_DJGPP),1)
STATIC_METHOD = -DUSE_LD_WRAP
else
STATIC_METHOD = -DUSE_LIBC_HOOKS
DYNAMIC_METHOD = -DUSE_LIBC_HOOKS
endif

ifeq ($(USING_DJGPP),1)
SYM_LIB = -ldbg
endif

SRCS = Makefile TODO README NEWS COPYING do-syms.c run-yamd.in \
	yamd-gcc.c yamd.c first.c tests/test*.c tests/Makefile \
	 tests/main.c dbgcom.dif gdb.dif	

SEDIFY=sed 	-e "s,@PREFIX@,$(strip $(PREFIX)),g" \
		-e "s,@BINDIR@,$(strip $(BINDIR)),g" \
	 	-e "s,@LIBDIR@,$(strip $(LIBDIR)),g" \
		-e "s,@VERSION@,$(strip $(VERSION)),g"

ifneq ($(USING_DJGPP),1)
EXE=
else
EXE=.exe
endif

ifneq ($(USING_DJGPP),1)
DYNAMIC = libyamd-dynamic.so
endif

all : libyamd.a libyamdf.a $(DYNAMIC) do-syms$(EXE) run-yamd \
	 yamd-$(BASECC)$(EXE) yamd-$(BASECXX)$(EXE)

%.o : %.c
	$(CC) -c $(FINAL_CFLAGS) $(STATIC_METHOD) -o $@ $<

%.os : %.c
	$(CC) -fPIC -c $(FINAL_CFLAGS) $(DYNAMIC_METHOD) -o $@ $<

do-syms$(EXE) : do-syms.o
	$(CC) $(LDFLAGS) -o $@ $^ $(SYM_LIB)

libyamd.a : yamd.o
	ar rcs $@ $^

# File that gets linked first. 
libyamdf.a : first.o
	ar rcs $@ $^

libyamd-dynamic.so : yamd.os first.os
	$(CC) -shared -o $@ $^

run-yamd : run-yamd.in Makefile
	$(SEDIFY) < $< > $@
	chmod a+x $@

# yamd-gcc : yamd-gcc.in Makefile
# 	$(SEDIFY) < $< > $@
#	chmod a+x $@

yamd-$(BASECC).o : yamd-gcc.c
	$(CC) $(FINAL_CFLAGS) $(STATIC_METHOD) -DGCC=\"$(STRIPCC)\" -c -o $@ $<

yamd-$(BASECC)$(EXE) : yamd-$(BASECC).o
	$(CC) $(LDFLAGS) -o $@ $<

ifneq ($(CXX),)
yamd-$(BASECXX).o : yamd-gcc.c
	$(CC) $(FINAL_CFLAGS) $(STATIC_METHOD) -DGCC=\"$(strip $(STRIPCXX))\" -c -o $@ $<

yamd-$(BASECXX)$(EXE) : yamd-$(BASECXX).o
	$(CC) $(LDFLAGS) -o $@ $<

endif

DIST_DIR_NAME=yamd-$(VERSION)

dist-dir : $(SRCS)
	rm -rf $(DIST_DIR_NAME)
	mkdir $(DIST_DIR_NAME)
	cp -P $(SRCS) $(DIST_DIR_NAME)

tar : yamd-$(VERSION).tar.gz

yamd-$(VERSION).tar.gz : dist-dir
	rm -f $@
	tar -czf $@ $(DIST_DIR_NAME)

NODOTVERSION=$(subst .,,$(VERSION))

zip : yamd$(NODOTVERSION).zip

yamd$(NODOTVERSION).zip : dist-dir
	rm -f $@
	zip -r -l $@ $(DIST_DIR_NAME)

dist : tar zip

web : dist README
	cp yamd-$(VERSION).tar.gz yamd$(NODOTVERSION).zip \
		 $(HOME)/public_html/yamd
	cp README $(HOME)/public_html/yamd/README.txt
	cp NEWS $(HOME)/public_html/yamd/NEWS.txt

install : all
	install -d $(LIBDIR)
	install -d $(BINDIR)
	install -m 0644 libyamd.a $(LIBDIR)
	install -m 0644 libyamdf.a $(LIBDIR)
ifneq ($(DYNAMIC),)
	install -m 0755 $(DYNAMIC) $(LIBDIR)
endif
	install -m 0755 yamd-$(CC)$(EXE) run-yamd do-syms$(EXE) $(BINDIR)
ifneq ($(CXX),)
	install -m 0755 yamd-$(CXX)$(EXE) $(BINDIR)
endif

clean :
	rm -f *.a *.o *.os *.so *.exe
	rm -f run-yamd yamd-gcc do-syms
	$(MAKE) -C tests clean

test : libyamd.a
	$(MAKE) -C tests

# Development stuff.

DEBUGFLAGS = -g

debug :
	$(MAKE) $(MFLAGS) CFLAGS="$(CFLAGS) $(DEBUGFLAGS)" all test

.PHONY : all clean dist zip tar web install test dist-dir




#  This file and the rest of YAMD is copyright (C) 1999 by Nate Eldredge. 
#  There is no warranty whatever; I disclaim responsibility for any 
#  damage caused.  Released under the GNU General Public License (see the
#  file COPYING).
