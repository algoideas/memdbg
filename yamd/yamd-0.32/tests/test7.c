#include <stdlib.h>
#include <string.h>

char msg[] = "strdup overrun";

void test(void)
{
  char *p;
  p = strdup("Hello");
  p[10] = 'x';
}
