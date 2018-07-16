#include <stdio.h>
#include <stdlib.h>

static void c (void) __attribute__((constructor));
static void c (void)
{
  char *p;
  printf("Constructor test, should crash\n");
  p = malloc(10);
  p[11] = 0;
}

/* Unused; to fit into main.c */
char msg[] = "";
void test() {}
