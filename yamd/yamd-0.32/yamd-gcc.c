/*  This file and the rest of YAMD is copyright (C) 1999 by Nate Eldredge. */
/*  There is no warranty whatever; I disclaim responsibility for any */
/*  damage caused.  Released under the GNU General Public License (see the */
/*  file COPYING). */

/* This could be a very simple shell script, but DJGPP may not have bash... */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* #define DEBUG */

#ifndef YAMD_VERSION
#define YAMD_VERSION "unknown (compilation botch)"
#endif

#ifndef GCC
#define GCC "gcc"
#endif

#ifdef __linux__
#define HAVE_MEMALIGN
#endif

char *wrapped_funcs[] = {
  "malloc",
  "realloc",
  "free",
#ifdef HAVE_MEMALIGN
  "memalign",
#endif
  NULL
};

char *gcc_pre_args[] = {
  "-u", "__yamd_hook_1",
  "-u", "__yamd_hook_2",
  "-lyamdf",
  NULL
};

char *gcc_post_args[] = {
  "-lyamd",
  NULL
};

/* FIXME: pass our argv[0] or "gcc"?  Now use our argv[0]. */

int main(int argc, char *argv[])
{
  int i, j;
  char **gccav;
  int linking = 1;

  /* Make sure linking is being done. */
  for (i = 1; i < argc; i++)
    {
      if ((strcmp(argv[i], "-c") == 0) ||
	  (strcmp(argv[i], "-E") == 0) ||
	  (strcmp(argv[i], "-S") == 0))
	{
	  linking = 0;
	  break;
	}
      if (strcmp(argv[i], "-v") == 0)
	fprintf(stderr, "YAMD version %s\n", YAMD_VERSION);
    }
  if (linking)
    {
      /* 100 = number of args we add.  Well, close anyway :) */
      gccav = alloca((argc + 100) * sizeof(char *));
      i = 0;
      gccav[i++] = GCC;

#ifdef USE_LD_WRAP
      {
	static char wrap_arg[1000];
	/* Make the wrap option. */
	strcpy(wrap_arg, "-Wl");
	for (j = 0; wrapped_funcs[j]; j++)
	  {
	    strcat(wrap_arg, ",--wrap,");
	    strcat(wrap_arg, wrapped_funcs[j]);
	  } 
	gccav[i++] = wrap_arg;
      }
#endif
      for (j = 0; gcc_pre_args[j]; j++)
	gccav[i++] = gcc_pre_args[j];
      for (j = 1; j < argc; j++)
	gccav[i++] = argv[j];
      for (j = 0; gcc_post_args[j]; j++)
	gccav[i++] = gcc_post_args[j];
      gccav[i] = NULL;
    }
  else /* not linking */
    {
      gccav = argv;
    }
#ifdef DEBUG
  printf("Execing:\n");
  for (i = 0; gccav[i]; i++)
    printf("\"%s\" ", gccav[i]);
  printf("\n");
  fflush(NULL);
#endif
  execvp(GCC, gccav);
  perror(GCC);
  exit(-1);
}
