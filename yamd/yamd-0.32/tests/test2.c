/* Tester for yamd. */

#include <stdlib.h>

char msg[] = "touch freed (should crash)";
void test(void)
{
  char *p;
  p = malloc(10);
  free(p);
  p[5] = 'h';
}
