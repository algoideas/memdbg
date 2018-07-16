#include <stdio.h>

extern char msg[];
extern void test(void);


int main(void)
{
  printf("%s\n", msg);
  test();
  return 0;
}
