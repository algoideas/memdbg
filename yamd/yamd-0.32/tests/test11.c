#include <stdio.h>
#include <stdlib.h>

static void c (void)
{
  char *p;
  p = malloc(10);
  p[11] = 0;
}

char msg[] = "Atexit test, should crash";
void test() { atexit(c); }
