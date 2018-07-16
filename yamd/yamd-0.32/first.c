/*  This file and the rest of YAMD is copyright (C) 1999 by Nate Eldredge. */
/*  There is no warranty whatever; I disclaim responsibility for any */
/*  damage caused.  Released under the GNU General Public License (see the */
/*  file COPYING). */

/* This is linked first on the command line. */

extern void __yamd_maybe_startup(void);
extern void __yamd_maybe_finish(void);

/* Make sure this module is linked. */
int __yamd_hook_2 asm ("__yamd_hook_2") = 0;

static void construct(void) __attribute__((constructor));
static void construct(void) { __yamd_maybe_startup(); }

static void destruct(void) __attribute__((destructor));
static void destruct(void) { __yamd_maybe_finish(); }
