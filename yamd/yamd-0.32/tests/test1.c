/* Tester for yamd. */

#include <stdlib.h>

char msg[] = "malloc overrun (should crash)";
void test(void)
{
  char *p;
  p = malloc(10);
  p[10] = 'h';
}
