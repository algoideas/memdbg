.PHONY:all

TARGERT_BIN := tst-mtrace

AT := @

CFLAGS += -g -D_GNU_SOURCE -Werror  -Wimplicit-int -Wreturn-type -Wimplicit-function-declaration

CC=gcc

CFLAGS += -I.

CPPFLAGS := -I.

CXXFLAGS := $(CXXFLAGS)

LDFLAGS :=


#mem_debug
CPPFLAGS += -I./
MTRACE_DEBUG_SRCS := $(foreach dir,./,$(wildcard $(dir)/*.c))
C_MTRACE_DEBUG_OBJS := $(foreach n,$(MTRACE_DEBUG_SRCS),$(addsuffix .o,$(basename ${n})))


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

tst-mtrace:$(C_MTRACE_DEBUG_OBJS)
	@$(AT)echo "BUILD_EXECUTABLE $(notdir $@)"
	$(CC) -o $@ $(C_MTRACE_DEBUG_OBJS) $(CFLAGS) -Wl,--start-group $(LDFLAGS) $(LIBS) -Wl,--end-group

#注意：不能进行strip
#@$(CROSS)-strip $@

#解析可以被容易理解的log
debug:
	mtrace tst-mtrace mmlog

############################################################################
	
clean:
	@echo $(TARGERT_BIN) | xargs rm -rf
	@-rm -f mmlog
	@-rm -f $(C_MTRACE_DEBUG_OBJS)   &>/dev/null
	@echo "Clean OK!"

