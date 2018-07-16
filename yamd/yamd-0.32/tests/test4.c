/* Tester for yamd. */

#include <stdlib.h>

char msg[] = "free bad (should complain)";
void test(void)
{
  char *p;
  p = malloc(10);
  free(p + 3);
}

