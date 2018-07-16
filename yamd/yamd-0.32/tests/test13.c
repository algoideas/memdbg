/* Tester for yamd. */

#include <stdlib.h>

char msg[] = "putenv free (should not barf)";
void test(void)
{
  /* putenv without an '=' should free the arg. */
  putenv("PATH");
}
