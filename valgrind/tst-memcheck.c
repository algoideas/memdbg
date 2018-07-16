#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int func()
{
	/* 1.申请内存，不释放，内存泄露 */
	int *array = malloc(8 * sizeof(int));
	
	/* 2.内存越界 */
	array[8] = 0xff;
	
	return 0;
}

int main(int argc, char* argv[])
{
	func();
    return 0;
}