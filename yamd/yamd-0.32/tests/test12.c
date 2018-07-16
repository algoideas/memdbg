#include <stdio.h>
#include <stdlib.h>

char msg[] = "Try freeing libc stuff (should have no errors)";
void test(void)
{
  fclose(stdin);
}
