/* Tester for yamd. */

#include <stdlib.h>

char msg[] = "malloc(0) (should issue warning)";
void test(void)
{
  malloc(0);
}
