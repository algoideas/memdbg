/* do-syms.c: Utility program to symificate yamd output. */


/*   This file and the rest of YAMD is copyright (C) 1999 by Nate Eldredge.  */
/*   There is no warranty whatever; I disclaim responsibility for any  */
/*   damage caused.  Released under the GNU General Public License (see the */
/*   file COPYING). */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef __DJGPP__
#include <debug/syms.h>
#endif

#define MAXLINE 500

typedef unsigned long addr;

#ifdef __linux__
static FILE *topipe = NULL;
static FILE *frompipe = NULL;

int start_syms(char *exe_name)
{
  pid_t pid;
  int to[2], from[2]; /* to/from the child */
  if (pipe(from) < 0 || pipe(to) < 0)
    {
      perror("pipe");
      return -1;
    }
  pid = fork();
  if (pid == 0)
    {
      /* Child */
      close(to[1]);
      close(from[0]);
      dup2(to[0], 0);
      dup2(from[1], 1);
      execlp("addr2line", "addr2line", "-f", "-e", exe_name, (char *)NULL);
      _exit(1);
    }
  else if (pid > 0)
    {
      /* Parent */
      close(to[0]);
      close(from[1]);
      topipe = fdopen(to[1], "w");
      frompipe = fdopen(from[0], "r");
      return 0;
    }
  else
    {
      perror("fork");
      return -1;
    }
}
#endif

#ifdef __DJGPP__
int start_syms(char *exe_name)
{
  syms_init(exe_name);
  return 0;
}
#endif

#ifdef __linux__
static void strip_trailing_newline(char *b)
{
  int i;
  i = strlen(b);
  if (b[i-1] == '\n')
    b[i-1] = '\0';
}

int get_sym(unsigned long a, char *buf)
{
  char funcbuf[MAXLINE];
  char linebuf[MAXLINE];

  fprintf(topipe, "%lx\n", a);
  fflush(topipe);
  if (fgets(funcbuf, MAXLINE, frompipe) == NULL)
    return -1;
  strip_trailing_newline(funcbuf);
  if (fgets(linebuf, MAXLINE, frompipe) == NULL)
    return -1;
  strip_trailing_newline(linebuf);
  sprintf(buf, "%s(%s)", linebuf, funcbuf);
  return 0;
}
#endif

#ifdef __DJGPP__
int get_sym(unsigned long a, char *buf)
{
  char *func, *file;
  unsigned long func_off = 0;
  int line = 0;
  func = syms_val2name(a, &func_off);
  file = syms_val2line(a, &line, 0 /* not exact */);
#define MAYBE(s) ((s) ? : "???")
  sprintf(buf, "%s:%d(%s+%ld)", MAYBE(file), line, MAYBE(func), func_off);
#undef MAYBE
  return 0;
}
#endif

#ifdef __linux__
int end_syms(void)
{
  fclose(topipe);
  fclose(frompipe);
  return 0;
}
#endif

#ifdef __DJGPP__
int end_syms(void)
{
  return 0;
}
#endif

int process(char *exe, FILE *in, FILE *out)
{
  char inbuf[MAXLINE];
  char symbuf[MAXLINE * 3];
  int in_traceback = 0;
  start_syms(exe);
  
  while (fgets(inbuf, MAXLINE, in) != NULL)
    {
      unsigned long a;
      if (strcmp(inbuf, "BEGIN TRACEBACK\n") == 0)
	{
	  in_traceback = 1;
	  continue;
	}
      if (strcmp(inbuf, "END TRACEBACK\n") == 0)
	{
	  in_traceback = 0;
	  continue;
	}
      if (in_traceback)
	putc('\t', out);
      if ((sscanf(inbuf, " [%lx]", &a) == 1)
	  || (sscanf(inbuf, " 0x%lx\n", &a) == 1))
	{
	  if (get_sym(a, symbuf) >= 0)
	    fputs(symbuf, out);
	}
      fputs(inbuf, out);
    }
  end_syms();
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc < 2)
    {
      fprintf(stderr, "Usage: %s exe-name <log_file\n", argv[0]);
      exit(2);
    }
  process(argv[1], stdin, stdout);
  return 0;
}
