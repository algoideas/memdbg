/* Yet Another Malloc Debugger */

/* For now, error checking mostly causes bombs.  Later, it will handle
   things gracefully. */

/*  This file and the rest of YAMD is copyright (C) 1999 by Nate Eldredge. */
/*  There is no warranty whatever; I disclaim responsibility for any */
/*  damage caused.  Released under the GNU General Public License (see the */
/*  file COPYING). */


/* Headers */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <math.h>

/* Configuration info */

#if ((defined(__GLIBC__)) && (__GLIBC__ >= 2))
#define GLIBC2 42
#endif 

#if (defined(GLIBC2) && (__GLIBC_MINOR__ >= 1))
#define GLIBC21
#endif

#ifdef GLIBC2
#define HAVE_MEMALIGN
#endif

#ifdef GLIBC21
#define HAVE_BACKTRACE_SYMBOLS
#include <execinfo.h>
#endif

#ifdef __linux__
#define HAVE_VALLOC
#ifndef GLIBC2
/* Might define sigcontext_struct instead.  Deal with it. */
#define sigcontext_struct sigcontext
#include <asm/sigcontext.h>
#endif
#endif

#ifdef __DJGPP__
#undef HAVE_VALLOC
#undef HAVE_MEMALIGN

#include <dpmi.h>
#include <sys/nearptr.h>
#include <sys/segments.h>
#include <crt0.h>
#include <setjmp.h>
#include <sys/exceptn.h>

#undef DJGPP_SIGNAL /* See comment at the #ifdef. */
#endif

/* #define DEBUG */
/* #define HASH_PROFILE */

/* Traceback stuff. */

/* Integer type which is like a pointer, and can be cast to and from. */

typedef unsigned long addr;

/* Shorthand. */
typedef unsigned char uchar;

/* Doesn't point at anything, but is distinct from NULL. */
#define BAD_POINTER ((void *)-1)

#define MAX_TRACEBACK_LEVELS 50

typedef addr TRACEBACK[MAX_TRACEBACK_LEVELS];

#define ENVIRONMENT_PREFIX "YAMD_"

/* Keeping track of which entry points did what. */
#define BY_NONE 0
#define BY_MALLOC 1
#define BY_REALLOC 2
#define BY_FREE 3
#define BY_MEMALIGN 4
#define BY_ALLOCA 5
#define BY_AUTO 6 /* Automatic freeing of alloca'ed blocks-- unimplemented */
#define BY_LITE 7

#define BYBITS 3

/* New algorithm.  We have several interlocking structures:
   - Hash table.  Chained with the hash_next field.
   - Linked list of all blocks, chained by all_next.
   - Linked lists of blocks allocated by malloc or memalign, chained
   by alignment_next. 
   - The realloc backlink. */
 
/* This thing is now rather large, but it's easier if it contains all
   the allocations we need to do. */

typedef struct block {
  /* Some of these may be redundant */
  addr block_addr; /* The address of the first page of the block */
  size_t block_size; /* Number of bytes we got, altogether */
  addr user_addr; /* Address we told the user */
  size_t user_size; /* Size the user is allowed */
  addr suffix_addr; /* Where the unmapped suffix pages start */
  size_t alignment;
  TRACEBACK where_alloced; /* Address of the function that allocated it. */
  TRACEBACK where_freed; /* Address where it was freed, or NULL */
  struct block *realloc_backlink;
  struct block *hash_next;
  struct block *all_next;
  struct block *alignment_next;
  unsigned who_alloced : BYBITS;
  unsigned who_freed : BYBITS;
} block; /* Should maybe be BLOCK or something? */

#define HASH_SIZE 499 /* Probably should be a large prime. */

static block *hash[HASH_SIZE];

static block *all_blocks = NULL;
static block *aligned_blocks = NULL; /* Those with non-default alignment */
static block *unaligned_blocks = NULL; /* With default alignment. */

#define HAS_DEFAULT_ALIGNMENT(b) ((b)->who_alloced != BY_MEMALIGN)

/* Magic. */
#define MAGIC_SIZE 8
static uchar magic[MAGIC_SIZE] = { 0xde, 0xad, 0xbe, 0xef,
				   0xba, 0xad, 0xca, 0xfe };
#ifdef __i386__
#define PGSZ 4096UL
#else /* well, maybe it'll happen someday */
#define PGSZ ((unsigned long)getpagesize())  /* Shorthand */
#endif

#define PAGEMASK (PGSZ - 1)

/* Variables corresponding to options. */

/* Alignment requirement for user blocks; should be a power of 2.
   One could even make it 1; that would give a speed penalty for
   the unaligned accesses, but should catch all overruns. */

static int default_alignment = 1; 

static int check_front = 0; /* as opposed to end */

#ifdef COMPLETE_MAGIC
/* At present, we just magic-fill the bytes between the end we're
   interested in (dependent on check_front) and the unmapped page.
   This option will magic-fill the bytes at the other end as well.
   But there are a lot of them, and so this is slow and involves some
   tedious arithmetic.  Implement it later if there seems to be a need
   for it. */
static int complete_magic = 0;
#endif


/* Fix corrupted blocks? */
static int repair_corrupted = 0;

/* Die if a corrupted block is found? */
static int die_on_corrupted = 1;

/* Filename to which we output. */
static const char *logfile_name = "-";

/* Logging */

#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERR 3

static int min_log_level = LOG_INFO;

/* Ugly way to make lack of snprintf a little safer */

#define MAX_PRINTF (PATH_MAX + 1024) /* let's be liberal */
#define LOG_BUF_SIZE (MAX_PRINTF * 4)

static char log_buf[LOG_BUF_SIZE];
static int log_buf_pos = 0;

static int log_fd = -1;

/* Some statistics. */
static size_t user_currently_allocated = 0; /* and not freed */
static size_t max_user_allocated = 0; /* max value of the above */
static size_t user_allocated = 0; /* whether freed or not */
static unsigned long n_allocations = 0;

static size_t internal_allocated = 0;
static size_t internal_mapped = 0;
static size_t max_internal_mapped = 0;

/* Anything much bigger than this becomes a negative int, which
   confuses the libc allocators.  It probably should never happen
   anyway.  */

#define WAY_TOO_BIG ((unsigned long)(2 * 1000 * 1000 * 1000))

#define YAMD_SO_NAME "yamd.so"
#define LD_PRELOAD_ENV "LD_PRELOAD"

#define CAST_ASSIGN(d,s) ((d) = ((typeof (d))(s)))

#define POINTER_FORMAT "%#08lx"

/* Symbol control */

#ifdef USE_LIBC_HOOKS
#define WRAPPER_LINKAGE static
#define WRAP(name) wrap_ ## name
#define REAL(name) name
#endif

#ifdef USE_LD_PRELOAD
#define WRAPPER_LINKAGE /* global */
#define WRAP(name) name 
#define REAL(name) __libc_ ## name
#endif

#ifdef USE_LD_WRAP
#define WRAPPER_LINKAGE /* global */
#define WRAP(name) __wrap_ ## name 
#define REAL(name) __real_ ## name
#endif

extern void * REAL(malloc) (size_t s);
WRAPPER_LINKAGE void * WRAP(malloc) (size_t s);

extern void * REAL(realloc) (void *p, size_t s);
WRAPPER_LINKAGE void * WRAP(realloc) (void * p, size_t s);


extern void REAL(free) (void *p);
WRAPPER_LINKAGE void WRAP(free) (void * p);

#ifdef HAVE_MEMALIGN
extern void * REAL(memalign) (size_t align, size_t size);
WRAPPER_LINKAGE void * WRAP(memalign) (size_t align, size_t size);
#endif

/* Hook to ensure we get linked.  The asm is to avoid underscore
   troubles. */
int __yamd_hook_1 asm ("__yamd_hook_1") = 0;

/* Perhaps someday we can use this to check a binary for containing
   YAMD.  In the meantime it's just a few bytes. */

static char some_text[] __attribute__((unused));
static char some_text[] = "YAMD version " YAMD_VERSION " was here";

/* Declarations */
static void die(void);
static int zap(addr p, size_t nb);
static addr do_valloc(size_t n);
static void mem_fill(uchar *dest, size_t dest_size, const uchar *src, size_t src_size);
static addr magic_check_range(addr start, addr end);
static void magic_fill_range(addr start, addr end);
static void insert_block(block *b);
static block *find_block_by_user_addr(addr a);
static block *find_block_by_any_addr(addr a);
static const char *get_entry_name(unsigned by_who);
static void log_flush(void);
static void log_vprintf(const char *fmt, va_list va);
static void log_printf(const char *fmt, ...);
static void log_event(int level, const char *desc);
static void log_detail(int level, const char *fmt, ...);
static void generate_any_traceback(TRACEBACK tb, addr start_eip, addr start_ebp, int eip_on_stack);
static void generate_traceback(TRACEBACK tb, addr eip);
static void dump_traceback(int level, TRACEBACK tb);
static void do_any_traceback(int level, addr eip, addr ebp, int eip_os);
static void do_traceback(int level, addr eip);
static void describe_block(int level, block *b);
static void check_block(block *b);
static void check_heap(void);
static void *do_malloc(size_t nbytes, size_t alignment, addr orig_caller, unsigned by_who, block *backlink);
static block *block_to_free(void *user, addr orig_caller, unsigned by_who);
static void do_free_block(block *b, addr orig_caller, unsigned by_who);
static void print_footer(void);
static void print_header(void);
static void handle_page_fault(addr address, int write, addr eip, addr ebp);
static void describe_address(int level, addr a);
static void *lite_malloc(size_t n);
static void lite_free(void *p);
static void lite_free_block(block *b);
/* --------------------------END DECLS------------------------------ */

/* Number of times we call __yamd_maybe_finish. */
#define TRIES_FOR_FINISH 3

static void startup(void);
static void finish(void);

void __yamd_maybe_startup(void);
void __yamd_maybe_finish(void);

static void die(void)
{
  log_flush();
  abort();
}

#ifdef USE_LIBC_HOOKS
typedef struct {
  void * (*malloc_hook)(size_t s);
  void * (*realloc_hook)(void *p , size_t s );
  void (*free_hook)(void *p );
  void * (*memalign_hook)(size_t al, size_t s );
} hookset;

static hookset yamd_hooks = {
  WRAP(malloc),
  WRAP(realloc),
  WRAP(free),
  WRAP(memalign)
};

static hookset old_hooks = { NULL, NULL, NULL, NULL };

static void set_hooks(hookset *h)
{
  CAST_ASSIGN(__malloc_hook, h->malloc_hook);
  CAST_ASSIGN(__realloc_hook, h->realloc_hook);
  CAST_ASSIGN(__free_hook, h->free_hook);
  CAST_ASSIGN(__memalign_hook, h->memalign_hook);
}

static void get_hooks(hookset *h)
{
  CAST_ASSIGN(h->malloc_hook, __malloc_hook);
  CAST_ASSIGN(h->realloc_hook, __realloc_hook);
  CAST_ASSIGN(h->free_hook, __free_hook);
  CAST_ASSIGN(h->memalign_hook, __memalign_hook);
}
#else
typedef int hookset; /* should never be used */
#define set_hooks(h)
#define get_hooks(h)
#endif

#define FULL_MODE 1
#define LITE_MODE 2
#define NOCATCH_MODE 3

static int mode = LITE_MODE;

static int old_mode = LITE_MODE; /* so we can call OK_CATCH at first. */

#define NO_CATCH() do { 			\
  old_mode = mode;				\
  mode = NOCATCH_MODE;				\
  set_hooks(&old_hooks);			\
} while (0)

#define OK_CATCH() do {			\
  mode = old_mode;				\
  get_hooks(&old_hooks);			\
  set_hooks(&yamd_hooks);			\
} while (0)

/* Am I trying too hard to make this transparently changeable? */
#define MODE_VAR int __yamd_temp_mode
#define ENTER() do { __yamd_temp_mode = mode; mode = LITE_MODE; } while (0)
#define LEAVE() do { 			\
  mode = __yamd_temp_mode;			\
  if (mode == FULL_MODE) log_flush();           \
} while (0)
#define WAS_LITE_MODE (__yamd_temp_mode == LITE_MODE)

#define SHOULD_NOT_CATCH (mode == NOCATCH_MODE)

/* Utility. */

static inline unsigned long
round_down(unsigned long x, unsigned long mul)
{
  return x - (x % mul);
}

static inline unsigned long
round_up(unsigned long x, unsigned long mul)
{
  return round_down(x + (mul - 1), mul);
}


/* Make region untouchable. */

static int
zap(addr p, size_t nbytes)
{
  int v;
  /*  fprintf(stderr, "Doing mprotect(%p, %u, PROT_NONE)\n", p, nb); */
  v = mprotect((void *)p, nbytes, PROT_NONE);
  if (v != 0)
    perror("unmap: mprotect");
  return v;
}

#if 0  /* Not used now. */
static int
remap_pages(void *p, size_t np)
{
  int v;
  v = mprotect(p, np * PGSZ, PROT_READ | PROT_WRITE);
  if (v != 0)
    perror("unmap: mprotect");
  return v;
}
#endif

/* The low-level routines we use to get memory.
   FIXME: The naming has become misleading. */

#if defined(__linux__)
/* We know Linux has a good, fast mmap.  Use it, so as not to incur
   malloc's memory overhead. */
static void *
system_valloc(size_t nbytes)
{
  void *p;
  p = mmap(NULL, round_up(nbytes, PGSZ), PROT_READ | PROT_WRITE,
	   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED)
    return NULL;
  else
    return p;
}
#elif defined(HAVE_VALLOC)
#define system_valloc valloc
#else /* generic implementation */
static void *
system_valloc(size_t nbytes)
{
  addr a;
  a = (addr)REAL(malloc)(nbytes + PGSZ);
  return (void *)((a + PAGEMASK) & ~PAGEMASK);
}
#endif

static addr
do_valloc(size_t nbytes)
{
  void *p;
  NO_CATCH();
  p = system_valloc(nbytes);
  OK_CATCH();
  return (addr)p;
}

#if 0 /* Currently we never free memory.  Sad, but true. */
static void
free_pages(void *p, size_t npages)
{
  if (remap_pages(p, npages) == 0)
    REAL(free)(p);
}
#endif

/* Utility functions */

/* `mem_fill': Fill `dest_size' bytes of `dest' with repeating
   sequences of the `src_size' bytes from `src', aligned to `src_size'
   boundary. */

static void 
mem_fill(uchar *dest, size_t dest_size, const uchar *src, size_t src_size)
{
  size_t di;
  size_t si;
  si = di = 0;
  while (di < dest_size)
    {
      while (si < src_size && di < dest_size)
	dest[di++] = src[si++];
      /* Start si over again. */
      si = 0;
    }
}

static size_t big_magic_size = 0;
static uchar *big_magic = NULL; /* Filled on startup with as much magic
			    as we need. */
static inline void
maybe_grow_big_magic(size_t new)
{
  if (new > big_magic_size)
    {
      NO_CATCH();
      big_magic = REAL(realloc)(big_magic, new);
      OK_CATCH();
      /* What to do if it runs out? */
      if (!big_magic)
	{
	  log_event(LOG_ERR, "Out of memory for internal YAMD stuff");
	  die();
	}
      mem_fill(big_magic, new, magic, sizeof(magic));
    }
}

/* Compares blocks b1 and b2.  Returns offset by which they differ,
   or -1 if the first n bytes are the same. */

static inline 
ssize_t memcmp_w(uchar *b1, uchar *b2, size_t n)
{
  /* Some assembly might be useful here */
  size_t i = 0;
  while (i < n && b1[i] == b2[i]) i++;
  if (i == n)
    return -1;
  else
    return i;
}

static addr 
magic_check_range(addr start, addr end)
{
  ssize_t v;
  size_t sz = end - start;
  maybe_grow_big_magic(sz);
  v = memcmp_w((uchar *)start, big_magic, sz);
  if (v < 0)
    return 0;
  else
    return start + v;
}

static void
magic_fill_range(addr start, addr end)
{
  size_t sz = end - start;
  maybe_grow_big_magic(sz);
  memcpy((void *)start, big_magic, sz);
}

#ifdef COMPLETE_MAGIC
static void
magic_fill_block(block *b)
{
  magic_fill_range((addr )b->block_addr + PGSZ, (addr )b->user_addr);
  magic_fill_range((addr )b->user_addr + b->user_size, (addr )b->suffix_addr);
}
#endif

/* Block management. */

#define for_each_block(p) for (p = all_blocks; p; p = p->all_next)

#define for_each_block_by_alignment(p, head) \
  for (p = head; p; p = p->alignment_next) 

/* Should return a valid index into hash[]. */
/* We use this because the low-order bits probably aren't random, nor are
   the highest.  Here we get the middle, then shift and xor. */

/* #define HASH_FUNC(n) (((n) / PGSZ) % HASH_SIZE) */

#define HASH_FUNC(n) ((((n) / PGSZ) ^ (((n) / PGSZ) >> 8)) % HASH_SIZE)

static void
insert_block(block *b)
{
  /* Insert into the hash table. */
  int h;
  h = HASH_FUNC(b->user_addr);
  b->hash_next = hash[h];
  hash[h] = b;

  /* And into the all_blocks list */
  b->all_next = all_blocks;
  all_blocks = b;

  /* And into its alignment list */
  if (HAS_DEFAULT_ALIGNMENT(b))
    {
      b->alignment_next = unaligned_blocks;
      unaligned_blocks = b;
    }
  else
    {
      b->alignment_next = aligned_blocks;
      aligned_blocks = b;
    }
}

static block *
find_block_by_user_addr(addr a)
{
  block *p;
  for (p = hash[HASH_FUNC(a)]; p; p = p->hash_next)
    if (p->user_addr == a)
      return p;
  return NULL;
}

/* This need not be fast; it's only called in the event of an error. */
static block *
find_block_by_any_addr(addr a)
{
  block *p;
  for_each_block(p)
    if ((a >= p->block_addr) && (a < (p->block_addr + p->block_size)))
      return p;
  return NULL;
}

#ifdef HASH_PROFILE
static void
hash_profile(void)
{
  double avg;
  double variance = 0.0;
  int i;
  avg = ((double)n_allocations) / HASH_SIZE;
  for (i = 0; i < HASH_SIZE; i++)
    {
      int j = 0;
      block *p;
      for (p = hash[i]; p; p = p->hash_next)
	j++;
      variance += (pow(((double)j) - avg, 2.0) / (double)HASH_SIZE);
    }
  log_printf("Average chain length = %f, std dev = %f\n",
	  avg, sqrt(variance));
}
#endif      

static const char *
get_entry_name(unsigned by_who)
{
  static char *table[] = {
    [BY_NONE] "nobody",
    [BY_MALLOC] "malloc",
    [BY_FREE] "free",
    [BY_REALLOC] "realloc",
    [BY_MEMALIGN] "memalign",
    [BY_ALLOCA] "alloca",
    [BY_AUTO] "alloca auto-free",
    [BY_LITE] "lite-mode allocator"
  };
  return table[by_who];
}

/* Logging */

static void
log_flush(void)
{
  write(log_fd, log_buf, log_buf_pos);
  log_buf_pos = 0;
}

static void
log_vprintf(const char *fmt, va_list va)
{
  /* This is not at all safe; I really wish we always had vsnprintf */
  if (log_buf_pos + MAX_PRINTF >= LOG_BUF_SIZE)
    log_flush();
  log_buf_pos += vsprintf(log_buf + log_buf_pos, fmt, va);
  if (log_buf_pos + 1 >= LOG_BUF_SIZE)
    {
      /* Not a good thing. */
      static char msg[] = "YAMD: Log buffer overrun-- increase MAX_PRINTF" \
	" and recompile\n";
      write(2, msg, strlen(msg));
      abort();
    }
}

static void
log_printf(const char *fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  log_vprintf(fmt, va);
  va_end(va);
}

static void
log_event(int level, const char *desc)
{
  char *ls;
  if (level >= min_log_level)
    {
      switch (level)
	{
	case LOG_INFO: ls = "INFO"; break;
	case LOG_WARN: ls = "WARNING"; break;
	case LOG_ERR: ls = "ERROR"; break;
	default: ls = "uh oh, don't know this"; break;
	}
      log_detail(level, "\n%s: %s\n", ls, desc);
    }
}

static void
log_detail(int level, const char *fmt, ...)
{
  va_list vl;
  if (level >= min_log_level)
    {
      va_start(vl, fmt);
      log_vprintf(fmt, vl);
      va_end(vl);
    }
}

/* Generate a traceback and store it in `tb'.  If `eip_on_stack' is 1,
   `start_ebp' is a frame pointer somewhere below the caller at `start_eip'.
   Otherwise, `start_eip' is not on the stack; the traceback will start
   with it and continue with the function whose frame pointer is `start_ebp'.
*/

/* Standard GCC stack frame looks like:
   ...
   Return address
   Saved EBP  <-- EBP points here
   Local vars...
*/

#ifdef __linux__
/* Bother.  There isn't really any good way to find out the limits
   of the stack.  Guess we just have to trust the luser to have
   compiled without -fomit-frame-pointer and not scrogged the stack... */
#define STACK_ADDR_OK(a) ((a) != 0)
#endif

#ifdef __DJGPP__
extern int djgpp_end asm ("end");
#define STACK_ADDR_OK(a) (((a) >= (addr)&djgpp_end) && \
			  ((a) < (addr)__djgpp_selector_limit))
#endif

/* This code looks a bit suspicious with respect to GCC's new aliasing
   rules, but I think it's okay.  We only dereference pointers of type
   `addr *', so we aren't referring to the same object via pointers
   of different types.  Anyone who disagrees, please let me know. */

static void
generate_any_traceback(TRACEBACK tb, addr start_eip, addr start_ebp,
		       int eip_on_stack)
{
  /* Wow.  Here be lots of ugly typecasts. */
  addr ebp;
  addr last_ebp;
  addr eip;
  size_t i;
  
  if (eip_on_stack)
    {
      last_ebp = 0;
      ebp = start_ebp;
      eip = 0;  /* In case we abort immediately */
      /* The last test really needs to be done only once, but this
	 is cleaner */
      while (ebp > last_ebp && STACK_ADDR_OK(ebp))
	{
	  eip = *((addr *)ebp + 1);
	  last_ebp = ebp;
	  ebp = *(addr *)ebp;
	  if (eip == start_eip)
	    break;
	}
      if (eip != start_eip)
	{
	  /* We broke out because the frame address went wrong, or maybe
	     we reached the top.  Assume start_eip is right, but don't
	     go any farther than that. */
	  tb[0] = start_eip;
	  tb[1] = 0;
	  return;
	}
    }
  else
    {
      eip = start_eip;
      ebp = start_ebp;
    }
  
  i = 0;
  last_ebp = 0;
  tb[i++] = eip; /* Log the first one */

  /* The last test really needs to be done only once, but this
     is cleaner */
  while (i < MAX_TRACEBACK_LEVELS - 1 && ebp > last_ebp && STACK_ADDR_OK(ebp))
    {
      tb[i++] = *((addr *)ebp + 1);
      last_ebp = ebp;
      ebp = *(addr *)ebp;
    }
  tb[i] = 0;
}

/* The standard case, where we want a traceback of our callers */
static void
generate_traceback(TRACEBACK tb, addr eip)
{
  generate_any_traceback(tb, eip, (addr)__builtin_frame_address(0), 1);
}

static void
dump_traceback(int level, TRACEBACK tb)
{
  size_t i;
  log_detail(level, "BEGIN TRACEBACK\n"); /* to allow indentation */
#ifdef HAVE_BACKTRACE_SYMBOLS
  if (level >= min_log_level)
    {
      for (i = 0; tb[i] != 0; i++) ;
      log_flush();
      backtrace_symbols_fd((void **)tb, i, log_fd);
    }
#else
  for (i = 0; tb[i] != 0; i++)
    {
      log_detail(level, "  " POINTER_FORMAT "\n", tb[i]);
    }
#endif
  log_detail(level, "END TRACEBACK\n");
}

static void
do_any_traceback(int level, addr eip, addr ebp, int eip_os)
{
  TRACEBACK buf;
  generate_any_traceback(buf, eip, ebp, eip_os);
  dump_traceback(level, buf);
}

static void
do_traceback(int level, addr eip)
{
  TRACEBACK buf;
  generate_traceback(buf, eip);
  dump_traceback(level, buf);
}

static void
describe_block(int level, block *b)
{
  log_detail(level, "Address " POINTER_FORMAT ", size %u\n", b->user_addr, b->user_size);
  log_detail(level, "Allocated by %s ",
	     get_entry_name(b->who_alloced));
  if (b->who_alloced == BY_MEMALIGN)
    log_detail(level, "(alignment %u) ", b->alignment);
  log_detail(level, "at\n");
  dump_traceback(level, b->where_alloced);
  if (b->who_freed != BY_NONE)
    {
      if (b->who_freed == BY_AUTO)
	log_detail(level, "Automatically freed\n");
      else
	{
	  log_detail(level, "Freed by %s at\n",
		     get_entry_name(b->who_freed));
	  dump_traceback(level, b->where_freed);
	}
    }
  if (b->who_alloced == BY_REALLOC)
    {
      if (b->realloc_backlink == BAD_POINTER)
	{
	  log_detail(level, "Realloced from bad pointer\n");
	}
      else if (b->realloc_backlink == NULL)
	{
	  log_detail(level, "Realloced from NULL\n");
	}
      else
	{
	  log_detail(level, "Realloced from block:\n");
	  describe_block(level, b->realloc_backlink);
	}
    }
}

static void
handle_bad_magic(block *b, addr where)
{
  log_event(LOG_ERR, "Corrupted block");
  log_detail(LOG_ERR, "Bad magic bytes at " POINTER_FORMAT ", part of this block:\n", where);
  describe_block(LOG_ERR, b);
  log_detail(LOG_ERR, "Address in question is at offset %d\n",
	     where - b->user_addr);
  if (die_on_corrupted)
    {
      log_detail(LOG_ERR, "Dumping core\n");
      die();
    }
  if (repair_corrupted)
    {
      log_detail(LOG_ERR, "Fixing\n");
      /* Leave it to check_block to actually fix it, so it can catch
	 corruption at the other end first. */
    }
  else
    {
      log_detail(LOG_ERR, "Leaving as is\n");
    }
}

static void
check_block(block *b)
{
  addr badp;
  addr s, e;
  /* If check_front, we'd have nothing to do, so we'd better not
     be called in that case. */
  if (b->who_freed != BY_NONE)
    return;  /* We can't touch this area */
  if (b->who_alloced == BY_LITE)
    return; /* we don't want to know */
#ifdef COMPLETE_MAGIC      
  s = (addr )(b->block_addr + PGSZ);
  e = (addr )(b->user_addr);
  /* incomplete */
#endif

  /* The end */
  s = (b->user_addr + b->user_size);
  e = b->suffix_addr;
  badp = magic_check_range(s, e);
  if (badp)
    {
      handle_bad_magic(b, badp);
      magic_fill_range(s, e);
    }
}

static void
check_heap(void)
{
  block *p;
  /* Optimization. */
  if (check_front)
    return; /* Always nestled directly against a zapped page. */

  if (default_alignment > 1)
    for_each_block_by_alignment(p, unaligned_blocks)
      check_block(p);

  for_each_block_by_alignment(p, aligned_blocks)
    check_block(p);
}

static void *
lite_malloc(size_t nbytes)
{
  block *b;
  void *p;
  NO_CATCH();
  b = REAL(malloc)(sizeof(block));
  p = REAL(malloc)(nbytes);
  OK_CATCH();
  if (!b || !p)
    return NULL; /* FIXME: Not nice when memory low */
  b->user_addr = b->block_addr = (addr)p;
  b->user_size = b->block_size = nbytes;
  b->who_alloced = BY_LITE;
  b->who_freed = BY_NONE;
  b->realloc_backlink = NULL;
  /* Should be all we need to keep everyone else away from this. */
  insert_block(b);
  return p;
}

/* This is starting to get hairy. */
static void *
do_malloc(size_t nbytes, size_t alignment, addr orig_caller, 
	  unsigned by_who, block *backlink)
{
  block *b;
  int nomem = 0; /* Might a goto actually be cleaner?? */

  check_heap(); /* As long as we have control... */
  
  if (nbytes > WAY_TOO_BIG)
    {
      log_event(LOG_ERR, "Ridiculous allocation");
      log_detail(LOG_ERR, "At\n");
      do_traceback(LOG_ERR, orig_caller);
      log_detail(LOG_ERR, "attempt to %s %u bytes, which is way too big\n",
		 get_entry_name(by_who), nbytes);
      return NULL;
    }
  NO_CATCH();
  b = REAL(malloc)(sizeof(block));
  OK_CATCH();
  if (!b)
    nomem = 1;
  else
    {
      size_t ca; /* controlling alignment, in bytes */
      size_t user_piece_size; /* size of the piece not guarded */
      addr user_piece_start;
      user_piece_size = round_up(nbytes, PGSZ);
      ca = round_up(alignment, PGSZ);
      /* 1 addded for the ending guard page */
      b->block_size = user_piece_size + ca + PGSZ;
      b->block_addr = (addr)do_valloc(b->block_size);
      if (b->block_addr)
	{
	  user_piece_start = round_up(b->block_addr + PGSZ, ca);
	  b->suffix_addr = user_piece_start + user_piece_size;
	  zap(b->block_addr, user_piece_start - b->block_addr);
	  zap(b->suffix_addr, (b->block_addr + b->block_size) - b->suffix_addr);
	  if (check_front)
	    b->user_addr = user_piece_start;
	  else
	    {
	      b->user_addr = (b->suffix_addr - nbytes) & ~(alignment - 1);
	      magic_fill_range(b->user_addr + nbytes, b->suffix_addr);
	    }
#ifdef DEBUG
	  assert(b->suffix_addr >= b->user_addr);
	  assert((b->user_addr & (alignment - 1)) == 0);
	  bzero((void *)b->user_addr, nbytes); /* make sure it's touchable */
#endif
	}
      else /* no memory */
	{
	  nomem = 1;
	}
    }
  if (nomem)
    {
      NO_CATCH();
      if (b) REAL(free)(b);
      OK_CATCH();
      /* Should this be LOG_WARN? */
      log_event(LOG_INFO, "Failed allocation");
      log_detail(LOG_INFO, "Failed to %s %u bytes (aligned to %u) at\n", 
		 get_entry_name(by_who), nbytes, alignment);
      do_traceback(LOG_INFO, orig_caller);
      return NULL;
    }
  /* Okay, set it all up. */
  b->user_size = nbytes;
  b->alignment = alignment;
  generate_traceback(b->where_alloced, orig_caller);
  b->who_alloced = by_who;
  b->who_freed = BY_NONE;
  b->realloc_backlink = backlink;
#ifdef COMPLETE_MAGIC
  if (complete_magic)
    magic_fill_block(b);
#endif
  insert_block(b);
  /* Lies, damn lies, and... */
  user_currently_allocated += nbytes;

  if (user_currently_allocated > max_user_allocated)
    max_user_allocated = user_currently_allocated;
  user_allocated += nbytes;
  n_allocations++;
  
  internal_allocated += b->block_size; /* total size allocated */
  internal_mapped += (b->suffix_addr - (b->user_addr & ~PAGEMASK));
  if (internal_mapped > max_internal_mapped)
    max_internal_mapped = internal_mapped;

  if (nbytes == 0)
    {
      log_event(LOG_WARN, "Zero-byte allocation");
      describe_block(LOG_WARN, b);
    }
  else
    {
      log_event(LOG_INFO, "Normal allocation of this block");
      describe_block(LOG_INFO, b);
    }
  return (void *)b->user_addr;
}

WRAPPER_LINKAGE 
void *
WRAP(malloc)(size_t n )
{
  void *p;
  MODE_VAR;
  if (SHOULD_NOT_CATCH)
    return REAL(malloc)(n);
  ENTER();
  if (WAS_LITE_MODE)
    p = lite_malloc(n);
  else
    p = do_malloc(n, default_alignment, (addr)__builtin_return_address(0), BY_MALLOC, NULL);
  LEAVE();
  return p;
}

static inline int
log_base_2(unsigned long x)
{
  int i;
  i = -1;
  while (x != 0)
    {
      x >>= 1;
      i++;
    }
  return i;
}

#ifdef HAVE_MEMALIGN


static void *
lite_memalign(size_t alignment, size_t nbytes)
{
  block *b;
  void *p;
  NO_CATCH();
  b = REAL(malloc)(sizeof(block));
  p = REAL(memalign)(alignment, nbytes);
  OK_CATCH();
  if (!b || !p)
    return NULL; /* FIXME: Not nice when memory low */
  b->user_addr = b->block_addr = (addr)p;
  b->user_size = b->block_size = nbytes;
  b->who_alloced = BY_LITE;
  b->who_freed = BY_NONE;
  b->realloc_backlink = NULL;
  /* Should be all we need to keep everyone else away from this. */
  insert_block(b);
  return p;
}

WRAPPER_LINKAGE
void *
WRAP(memalign)(size_t alignment, size_t size )
{
  void *p;
  int t;
  MODE_VAR;
  if (SHOULD_NOT_CATCH)
    return REAL(memalign) (alignment, size);
  ENTER();
  if (WAS_LITE_MODE)
    p = lite_memalign(alignment, size);
  else
    {
      /* Check alignment for sanity */
      if (alignment > WAY_TOO_BIG)
	{
	  log_event(LOG_ERR, "Ridiculous alignment");
	  log_detail(LOG_ERR, "At\n");
	  do_traceback(LOG_ERR, (addr)__builtin_return_address(0));
	  log_detail(LOG_ERR, "attempt to memalign with %u byte alignment, which is way too big\n",
		     alignment);
	  LEAVE();
	  return NULL;
	}      
      t = log_base_2(alignment);
      if (t < 0 || alignment != (1UL << t))
	{
	  size_t new_alignment = 1UL << (t + 1);
	  log_event(LOG_ERR, "Alignment not power of 2");
	  log_detail(LOG_ERR, "At\n");
	  do_traceback(LOG_ERR, (addr)__builtin_return_address(0));
	  log_detail(LOG_ERR, "Attempt to memalign with %u byte alignment, which is not a power of 2\n", alignment);
	  log_detail(LOG_ERR,  "Using alignment of %u instead\n", new_alignment);
	  if (new_alignment > WAY_TOO_BIG)
	    {
	      log_detail(LOG_ERR, "Oops, that's too big, giving up.\n");
	      LEAVE();
	      return NULL;
	    }
	  alignment = new_alignment;
	}
      p = do_malloc(size, alignment, (addr)__builtin_return_address(0), BY_MEMALIGN, NULL);
    }
  LEAVE();
  return p;
}
#endif

/* KLUDGE: Returns block * */

static block *
block_to_free(void *user, addr orig_caller, unsigned by_who)
{
  block *b;

  check_heap(); /* Got to do it sometime */
  
  if (!user && by_who != BY_REALLOC) /* realloc(NULL, ...) is OK */
    {
      log_event(LOG_WARN, "Free of null pointer");
      log_detail(LOG_WARN, "At\n");
      do_traceback(LOG_WARN, orig_caller);
      log_detail(LOG_WARN, "Attempt to %s null pointer\n",
		 get_entry_name(by_who));
      return NULL;
    }
      
  b = find_block_by_user_addr((addr)user);
  if (!b)
    {
      log_event(LOG_ERR, "Free of errnoneous pointer");
      log_detail(LOG_ERR, "At\n");
      do_traceback(LOG_ERR, orig_caller);
      log_detail(LOG_ERR, "Freeing erroneous pointer " POINTER_FORMAT "\n", user);
      describe_address(LOG_ERR, (addr)user);
      return NULL;
    }
  if (b->who_freed != BY_NONE)
    {
      log_event(LOG_ERR, "Multiple freeing");
      log_detail(LOG_ERR, "At\n");
      do_traceback(LOG_ERR, orig_caller);
      log_detail(LOG_ERR, "%s of pointer already freed\n",
		 get_entry_name(by_who));
      describe_block(LOG_ERR, b);
      return NULL;
    }
  return b;
}

static void do_free_block(block *b, addr orig_caller, unsigned by_who)
{
  if (b->who_alloced == BY_LITE)
    {
      lite_free_block(b);
      return;
    }
  zap(b->block_addr, b->block_size);
  b->who_freed = by_who;
  if (by_who != BY_AUTO)
    generate_traceback(b->where_freed, orig_caller);
  /* We make sure that the traceback of an auto-freed block isn't used. */
  user_currently_allocated -= b->user_size;
  internal_mapped += (b->suffix_addr - (b->user_addr & ~PAGEMASK));
  log_event(LOG_INFO, "Normal deallocation of this block");
  describe_block(LOG_INFO, b);
}

static void
lite_free_block(block *b)
{
  b->who_freed = BY_LITE;
#if 0 /* Enable this later */
  if (b->who_alloced == BY_LITE)
    {
      NO_CATCH();
      REAL(free)((void *)b->user_addr);
      OK_CATCH();
    }
#endif
}

static void
lite_free(void *p)
{
  block *b;
#ifdef DEBUG
  /* We don't expect any errors here, but just for paranoia... */
  b = block_to_free(p, 0, BY_LITE);
#else
  b = find_block_by_user_addr((addr)p);
#endif
  if (b)
    lite_free_block(b);
}

WRAPPER_LINKAGE
void
WRAP(free) (void *p )
{
  MODE_VAR;
  block *b;
  if (SHOULD_NOT_CATCH)
    {
      REAL(free)(p);
      return;
    }
  ENTER();
  if (WAS_LITE_MODE)
    lite_free(p);
  else if ((b = block_to_free(p, (addr)__builtin_return_address(0), BY_FREE)) != NULL)
    do_free_block(b, (addr)__builtin_return_address(0), BY_FREE);
  LEAVE();
}

static void *
do_realloc(void *p, size_t s, addr orig_caller)
{
  void *q;
  block *b;
  if (p)
    {
      b = block_to_free(p, orig_caller, BY_REALLOC);
      if (!b)
	b = BAD_POINTER; /* not NULL, since reallocing from NULL
			    is not the same as reallocing from a bad
			    pointer. */
    }
  else
    {
      b = NULL;
    }
  q = do_malloc(s, default_alignment, orig_caller, BY_REALLOC, b);
  if (b && b != BAD_POINTER)
    {
      size_t ncpy;
      if (s < b->user_size)
	ncpy = s;
      else
	ncpy = b->user_size;
      memcpy(q, (void *)b->user_addr, ncpy);
      do_free_block(b, orig_caller, BY_REALLOC);  
    }
  return q;
}

static void *
lite_realloc(void *p, size_t s)
{
  block *b;
  void *q;
  size_t ncpy;
#ifdef DEBUG
  /* We don't expect any errors here, but just for paranoia... */
  b = block_to_free(p, 0, BY_LITE);
#else
  b = find_block_by_user_addr((addr)p);
#endif
  if (!b)
    {
      /* Hmm.  Not a good thing. */
      return NULL;
    }
  q = lite_malloc(s);
  if (!q)
    {
      return NULL;
    }
  if (s < b->user_size)
    ncpy = s;
  else
    ncpy = b->user_size;
  memcpy(q, (void *)b->user_addr, ncpy);
  lite_free_block(b);  
  return q;
}

WRAPPER_LINKAGE
void *
WRAP(realloc)(void *p, size_t s)
{
  MODE_VAR;
  void *q;
  if (SHOULD_NOT_CATCH)
    return REAL(realloc)(p, s);
  ENTER();
  if (WAS_LITE_MODE)
    q = lite_realloc(p, s);
  else
    q = do_realloc(p, s, (addr)__builtin_return_address(0));
  LEAVE();
  return q;
}

static void
describe_address(int level, addr a)
{
  block *b;
  b = find_block_by_any_addr(a);
  if (b)
    {
      int ofs;
      log_detail(level, "Seems to be part of this block:\n");
      describe_block(level, b);
      ofs = a - b->user_addr;
      log_detail(level, "Address in question is at offset %d",
		 ofs);
      if (ofs >= 0 && ofs < (int)b->user_size)
	log_detail(level, " (in bounds)\n");
      else
	log_detail(level, " (out of bounds)\n");
    }
  else
    {
      log_detail(level, "Seems not to be associated with any block.\n");
    }
}

void
__yamd_describe_address(void *a)
{
  /* HACK HACK HACK */
  /* This is intended for debuggers, so make it show up. */
  int ofd;
  int oll;
  log_flush();
  ofd = log_fd;
  log_fd = 2; /* stderr */
  oll = min_log_level;
  min_log_level = 0;

  describe_address(LOG_INFO, (addr)a);
  log_flush();

  log_fd = ofd;
  min_log_level = oll;
}

/* Hmm.  This is probably not overly safe; we call printf and such
   from within a signal handler.  If the crash was inside a stdio function,
   its state might be funny and things could get very screwed up. */

static void disclaimer(void)
{
  static char message[] = "This appears to be a non-malloc bug, dumping core\n";
  write(2, message, sizeof(message));
  signal(SIGSEGV, SIG_DFL);
  return;
}

#ifdef __linux__
#ifdef __i386__
static void sigsegv_handler(int signum, struct sigcontext ctx)
{
  (void)signum; /* shut the compiler up */
  /* Find out if this is a fault we're trying to catch */
  if (ctx.trapno != 14  /* Not a page fault */
      || !(ctx.err & 4)) /* Not a user access */
    {
      disclaimer();
      return;
    }
  /* Note that using cr2 here assumes that the base of DS is 0.
     Thank God for systems with real memory mapping... */
  handle_page_fault(ctx.cr2, ctx.err & 2, ctx.eip, ctx.ebp);
  return;  /* Resume the faulting instruction; it may or may not have
	      been fixed up */
}
#endif
#endif

#ifdef DJGPP_SIGNAL

/* Curses.  None of this clever hackish stuff works, since CWSDPMI
   zeroes out cr2 for its own purposes.  Getting the faulting cr2 is
   probably going to require hacking of CWSDPMI itself, or writing a
   newer-style exception handler (only for DPMI 1.0 and not supported
   by CWSDPMI).  So at present, let's just leave this stuff out and
   let the debuggers handle it. */

static int
get_ring(void)
{
  unsigned long desc[2];
  if (__dpmi_get_descriptor(_my_cs(), desc) < 0)
    return -1;
  /* DPL is bits 13 and 14 of upper word */
  return (desc[1] >> 13) & 0x2;
}

static void
sigsegv_handler(int sig)
{
  unsigned long cr2;
  unsigned long err_code;
  (void)sig; /* shut the compiler up */
#ifdef DEBUG
  printf("In signal handler\n");
#endif
  /* Misnamed; member `signum' is really the exception number.  14 ==
     page fault. */
  if (__djgpp_exception_state->__signum != 14)
    {
#ifdef DEBUG
      printf("Bad exception number %ld\n", __djgpp_exception_state->__signum);
#endif 
      disclaimer();
      return;
    }
  if (get_ring() != 0)
    return; /* without cr2 we can't do much */
  asm("movl %%cr2, %0" : "=r" (cr2));
  /* Undocumented feature.  From dpmiexcp.c-- MAY CHANGE! */
  err_code = __djgpp_exception_state->__sigmask & 0xffff;
  /* cr2 is linear address, so we must adjust. */
#ifdef DEBUG
  printf("cr2 = %#08lx\n", cr2);
  printf("base = %#08lx\n", (unsigned long)__djgpp_base_address);
  printf("eip = %#08lx\n", __djgpp_exception_state->__eip);
  printf("ebp = %#08lx\n", __djgpp_exception_state->__ebp);
  printf("err = %lx\n", err_code);
#endif
  handle_page_fault(cr2 - __djgpp_base_address,
		    err_code & 2, 
		    __djgpp_exception_state->__eip,
		    __djgpp_exception_state->__ebp);
  return; /* and die! */
}
#endif

static void
handle_page_fault(addr address, int write, addr eip, addr ebp)
{
  block *b;
  if (SHOULD_NOT_CATCH)
    {
      /* If YAMD shouldn't run, we're probably inside it and so
	 the crash was caused by us. */
      signal(SIGSEGV, SIG_DFL);
      return;
    }
  NO_CATCH(); /* is this really correct? */
  if (!(b = find_block_by_any_addr(address)))
    {
      disclaimer();
      return;
    }
  signal(SIGSEGV, SIG_DFL);
  log_event(LOG_ERR, "Crash");
  do_any_traceback(LOG_ERR, eip, ebp, 0);
  log_detail(LOG_ERR, "Tried to %s address " POINTER_FORMAT "\n",
	     (write) ? "write" : "read", address);
  describe_address(LOG_ERR, address);
  log_detail(LOG_ERR, "Will dump core after checking heap.\n");
  check_heap();
#if 0  /* Tread lightly on the core dump */
  print_footer();
#endif
  log_flush();
  return;  /* Resume the faulting instruction */
}

#define ENVIRON_INT 1
#define ENVIRON_STRING 2

struct environment_entry {
  char *name;
  int type;
  void *valuep;
};

static struct environment_entry environment_entries[] = {
  { "DEFAULT_ALIGNMENT", ENVIRON_INT, &default_alignment },
  { "LOGFILE_NAME", ENVIRON_STRING, &logfile_name },
  { "LOGFILE", ENVIRON_STRING, &logfile_name }, /* nicer for users */
  { "LOGLEVEL", ENVIRON_INT, &min_log_level },
  { "REPAIR_CORRUPTED", ENVIRON_INT, &repair_corrupted },
  { "DIE_ON_CORRUPTED", ENVIRON_INT, &die_on_corrupted },
  { "CHECK_FRONT", ENVIRON_INT, &check_front },
#ifdef COMPLETE_MAGIC
  { "COMPLETE_MAGIC", ENVIRON_INT, &complete_magic },
#endif
  { NULL, 0, NULL }
};

static void
parse_environment(void)
{
  char buf[200];
  struct environment_entry *env;
  for (env = environment_entries; env->name != NULL; env++)
    {
      char *p;
      strcpy(buf, ENVIRONMENT_PREFIX);
      strcat(buf, env->name);
      p = getenv(buf);
      if (p)
	{
	  switch(env->type)
	    {
	    case ENVIRON_INT:
	      {
		int t;
		char *tp;
		t = strtol(p, &tp, 0);
		if (tp)
		  *(int *)env->valuep = t;
		break;
	      }
	    case ENVIRON_STRING:
	      *(const char **)env->valuep = p;
	      break;
	    }
	}
    }
}

/* Set LD_PRELOAD for exec'd programs, possibly to prevent children
   from having YAMD loaded. */
static void set_child_preload(void)
{
  /* YAMD_CHILD_LD_PRELOAD is set for us by the shell script. */
  char *s;
  s = getenv("YAMD_CHILD_LD_PRELOAD");
  if (s)
    {
      if (strlen(s) != 0)
	{
	  char *newbuf;
	  newbuf = alloca(strlen(LD_PRELOAD_ENV) + 1 + strlen(s) + 1);
	  /*                                      '='             '\0' */
	  strcpy(newbuf, LD_PRELOAD_ENV);
	  strcat(newbuf, "=");
	  strcat(newbuf, s);
	  putenv(newbuf);
	}
      else
	{
	  putenv(LD_PRELOAD_ENV); /* unset it */
	}
    }
}

/* Return process size in K. */
#ifdef __linux__
static unsigned long process_size(void)
{
  FILE *f;
  unsigned long s;
  char buf[100];
  f = fopen("/proc/self/status", "r");
  if (!f)
    return 0;
  while (fgets(buf, 100, f) != NULL)
    {
      if (sscanf(buf, "VmSize: %lu", &s) == 1)
	return s;
    }
  return 0;
}
#endif
#ifdef __DJGPP__
static unsigned long process_size(void)
{
  /* Probably not accurate.  mprotect(PROT_NONE) will uncommit pages,
     meaning they will not be swapped out and are effectively freed
     (since when physical memory becomes full they will be discarded
     and reused).  This has the effect of creating holes in the memory
     map, so we're not actually using all the memory in this range. */

  return (((unsigned long)sbrk(0)) - 0x1000) / 1024;
}
#endif

static void print_footer(void)
{
  time_t t;
  time(&t);
  /* ctime's string ends in \n */
  log_printf("\n*** Finished at %s", ctime(&t));  
  log_printf("Allocated a grand total of %lu bytes\n",
	  (unsigned long)user_allocated);
  log_printf("%lu allocations\n", n_allocations);
  log_printf("Average of %lu bytes per allocation\n",
	  user_allocated / (n_allocations ? n_allocations : 1));
  log_printf("Max bytes allocated at one time: %lu\n",
	  (unsigned long)max_user_allocated);
  log_printf("%lu K alloced internally / %lu K mapped now / %lu K max\n",
	  (unsigned long)internal_allocated / 1024,
	  (unsigned long)internal_mapped / 1024,
	  (unsigned long)max_internal_mapped / 1024);
#ifdef HASH_PROFILE
  hash_profile();
#endif
  log_printf("Virtual program size is %lu K\n", process_size());
  log_printf("End.\n");
}

static void check_memory_leaks(void)
{
  block *p;
  int nleaks = 0;
  unsigned long nbytes = 0;
  for_each_block(p)
    {
      /* Don't complain that libc is leaking memory. */
      if (p->who_alloced != BY_ALLOCA
	  && p->who_alloced != BY_LITE
	  && p->who_freed == BY_NONE)
	{
	  nleaks++;
	  nbytes += p->user_size;
	  log_event(LOG_WARN, "Memory leak");
	  describe_block(LOG_WARN, p);
	}
    }
  if (nleaks)
    {
      log_event(LOG_WARN, "Total memory leaks:");
      log_detail(LOG_WARN, "%d unfreed allocations totaling %lu bytes\n",
		 nleaks, nbytes);
    }
}

static void print_header(void)
{
  time_t t;
  log_printf("YAMD version %s\n", YAMD_VERSION);
  log_printf("Starting run: ");
#ifdef __linux__
  {
    FILE *cmdline;
    char buf[PATH_MAX];
    int len;
    cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline)
      {
	int c;
	while ((c = getc(cmdline)) != EOF)
	  {
	    if (c == 0) c = ' '; /* null separation in use */
	    /* Well, this oughta be plenty slow.  Would log_putc be
	       a good idea, or should I use a real buffer here? */
	    log_printf("%c", c);
	  }
	fclose(cmdline);
      }
    else
      log_printf("<unknown>");
    log_printf("\n");
    /* This will only be useful if they have the new dcache
       in the kernel (since mid 2.1 but not in 2.0). */
    len = readlink("/proc/self/exe", buf, PATH_MAX);
    if (len < 0)
      strcpy(buf, "<unknown>");
    else
      buf[len] = '\0'; /* readlink does not null-terminate. */
    log_printf("Executable: %s\n", buf);
  }
#endif
#ifdef __DJGPP__
  {
    int i;
    for (i = 0; i < __crt0_argc; i++)
      log_printf("%s ", __crt0_argv[i]);
    log_printf("\nExecutable: %s\n", __crt0_argv[0]);
  }
#endif
  log_printf("Virtual program size is %lu K\n", process_size());
  time(&t);
  log_printf("Time is %s\n", ctime(&t));
#define PRINT_VAR(v) log_printf("%s = %d\n", #v, v)
  PRINT_VAR(default_alignment);
  PRINT_VAR(min_log_level);
  PRINT_VAR(repair_corrupted);
  PRINT_VAR(die_on_corrupted);
  PRINT_VAR(check_front);
#ifdef COMPLETE_MAGIC
  PRINT_VAR(complete_magic);
#endif
#undef PRINT_VAR
}

#ifdef USE_LIBC_HOOKS
static void start_catching(void)
{
  OK_CATCH();
}

void (*__malloc_initialize_hook)(void) = start_catching;
#endif


/* HACK HACK HACK HACK HACK HACK HACK */
/* We want `startup' to be run before any constructors, and `finish'
   after all destructors and `atexit' functions.  The order depends in
   part on link order.  Therefore we call these from all possible
   places, and get the first or last as appropriate. */

void __yamd_maybe_startup(void)
{
  static int have_run = 0;
  if (!have_run)
    {
      have_run = 1;
      atexit(__yamd_maybe_finish);
      startup();
    }
  else
    return;
}

void __yamd_maybe_finish(void)
{
  static int tries = 0;
  if (++tries == TRIES_FOR_FINISH) /* This is the last try */
    finish();
  else
    return;
}

/* This file will be linked either first or last, so let's have a shot
   at constructing. */

static void construct(void) __attribute__((constructor));
static void construct(void) { __yamd_maybe_startup(); }

static void destruct(void) __attribute__((destructor));
static void destruct(void) { __yamd_maybe_finish(); }

static void startup(void) 
{
  static int initted = 0;
  if (initted)
    {
      fprintf(stderr, "Initted multiple times! Can't happen\n");
      return;
    }
  initted = 1;
  /* We are in lite mode. */
  parse_environment();
  set_child_preload(); 
  if (strcmp(logfile_name, "-") == 0)
    {
      log_fd = 2;
    }
  else
    {
      /* Would other perms. be a good idea? */
      log_fd = open(logfile_name, O_WRONLY | O_CREAT | O_TRUNC, 0600); 
      if (log_fd < 0)
	{
	  perror(logfile_name);
	  return;
	}
    }
  print_header();
#ifdef __DJGPP__
#ifdef DJGPP_SIGNAL
#ifdef DEBUG
  printf("Running in ring %d\n", get_ring());
#endif /* DEBUG */
  if (get_ring() == 0)
    signal(SIGSEGV, sigsegv_handler);
#endif /* DJGPP_SIGNAL */
#else
  signal(SIGSEGV, (void (*)(int))sigsegv_handler);  
#endif /* __DJGPP__ */
  mode = FULL_MODE; /* go go go! */
}

static void finish(void)
{
  mode = LITE_MODE;
  signal(SIGSEGV, SIG_DFL);
  check_heap(); /* One last time... */
  check_memory_leaks();
  print_footer();
  log_flush();
  close(log_fd);
}
