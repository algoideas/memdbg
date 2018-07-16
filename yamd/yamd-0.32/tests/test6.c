#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char msg[] = "realloc copies";

void test(void)
{
  char *p;
  p = malloc(10);
  strcpy(p, "Hello");
  p = realloc(p, 20);
  if (strcmp(p, "Hello") == 0)
    printf(" OK\n");
  else
    printf("fail\n");
}
