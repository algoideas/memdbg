/* Tester for yamd. */

#include <stdlib.h>

char msg[] = "multi free (should complain)";
void test(void)
{
  char *p;
  p = malloc(10);
  free(p);
  free(p);
}
