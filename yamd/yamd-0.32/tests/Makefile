ifdef DJDIR
USING_DJGPP=1
endif

CFLAGS = -g
CC = gcc

# TESTS = 1 2 3 4 5 6 7 8 9
TEST_BASENAMES = $(basename $(wildcard test*.c))

ifneq ($(USING_DJGPP),1)
all : 	$(addsuffix .dynamic,$(TEST_BASENAMES)) \
	$(addsuffix .static,$(TEST_BASENAMES))
else
all : $(addsuffix .exe,$(TEST_BASENAMES))
endif

.PRECIOUS : %.o

%.o : %.c
	$(CC) $(CFLAGS) -c $<


%.dynamic : %.o main.o
	$(CC) -o $@ $^

%.static : %.o main.o ../libyamd.a ../yamd-gcc
	../yamd-gcc -L.. -o $@ $< main.o

%.exe : %.o main.o ../libyamd.a
	../yamd-gcc -L.. -o $@ $< main.o

clean : 
	rm -f *.o *.static *.dynamic *.exe
