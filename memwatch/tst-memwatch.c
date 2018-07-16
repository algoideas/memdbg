#include <stdio.h>
#include "memwatch.h"

int main(int argc , char *argv[])
{
	 /* 1.memwatch初始化 */
    mwInit();
	
	 /* 2.malloc memory, but no free */
	malloc(32);

	 /* 3.执行memwatch的清除工作 */
	mwTerm();
	
	return 0;
}