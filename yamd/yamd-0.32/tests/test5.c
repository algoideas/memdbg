/* Tester for yamd. */

#include <stdlib.h>
#include <stdio.h>

char msg[] = "malloc underrun (should crash if CHECK_FRONT)";
void test(void)
{
  char *p;
  p = malloc(10);
  p[-1] = 42;
}
