#include <mcheck.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char **argv)
{
  /* 1.设置MALLOC_TRACE环境变量,指定检测结果文件名及生成路径 */
  setenv("MALLOC_TRACE", "mmlog", 1);
	
  /* 2.Enable memory usage tracing. */
  mtrace();
  
   /* 3.malloc memory. */
  char *nofree = (char *)malloc(32);

  /* 4.no free test. */
  //free(nofree);

  return 0;
}