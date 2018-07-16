# Makefile for tst-memwatch
# By MinJie.YU
.PHONY:all

TARGERT_BIN := tst-memwatch

#For memwatch
CFLAGS := -DMEMWATCH  -DMW_STDIO
CFLAGS +=  -g -D_GNU_SOURCE -Werror  -Wimplicit-int -Wreturn-type -Wimplicit-function-declaration

CC=gcc

#-Wunused-function

CFLAGS += -I.

CPPFLAGS := -I.

CXXFLAGS := $(CXXFLAGS)

LDFLAGS :=

#mem_debug
CPPFLAGS += -I./
MEM_DEBUG_SRCS := $(foreach dir,./,$(wildcard $(dir)/*.c))
C_MEM_DEBUG_OBJS := $(foreach n,$(MEM_DEBUG_SRCS),$(addsuffix .o,$(basename ${n})))


%.cpp.o:%.cpp
	@mkdir -p $(dir $@)
	$(AT)echo "  CXX	$@"
	@$(CXX) $(CXXFLAGS) $(CPPFLAGS) -fPIC -c $^ -o $@

%.o:%.c
	@mkdir -p $(dir $@)
	$(AT)echo "  CC	$(notdir $@)"
	$(AT)$(CC) $(CFLAGS) $(CPPFLAGS) -c  $^ -o $@

############################################################################

all:$(TARGERT_BIN)

tst-memwatch:$(C_MEM_DEBUG_OBJS)
	@$(AT)echo "BUILD_EXECUTABLE $(notdir $@)"
	@$(CC) -o $@ $(C_MEM_DEBUG_OBJS) $(CFLAGS) -Wl,--start-group $(LDFLAGS) $(LIBS) -Wl,--end-group

debug:
	./tst-memwatch

############################################################################
	
clean:
	@echo $(TARGERT_BIN) | xargs rm -rf
	@-rm -f memwatch.log
	@-rm -f $(C_MEM_DEBUG_OBJS)   &>/dev/null
	@echo "Clean OK!"

