#include <stdio.h>
#include <stdlib.h>

static void c (void) __attribute__((destructor));
static void c (void)
{
  char *p;
  p = malloc(10);
  p[11] = 0;
}

/* Unused; to fit into main.c */
char msg[] = "Destructor test, should crash";
void test() {}
