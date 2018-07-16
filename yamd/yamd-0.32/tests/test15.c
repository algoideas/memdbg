/* Tester for yamd. */

#define _GNU_SOURCE
#include <stdlib.h>

#ifdef __GNU_LIBRARY__
#include <malloc.h>
char msg[] = "memalign overrun (should complain)";
void test(void)
{
  char *p;
  p = memalign(4096, 1);
  p[3] = 'X';
}
#else
char msg[] = "Test of memalign, which you don't have (does nothing)";
void test(void) {}
#endif

