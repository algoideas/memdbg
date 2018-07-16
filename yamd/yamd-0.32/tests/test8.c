#include <stdlib.h>
#include <string.h>

char msg[] = "calloc overrun (should crash)";

void test(void)
{
  char *p;
  p = calloc(5, 1);
  p[10] = 'x';
}
