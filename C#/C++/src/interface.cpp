#include "interface.h"
#include <string.h>
#include <stdio.h>
char * test1(int length, const char * param)
{
	char *cResult= new char[length+strlen("s length is ")+1];
	sprintf(cResult, "%s's length is %d", param, length);
	return cResult;
}
int	test2(char * cResult)
{
	if(cResult)
		strcpy(cResult, "helloWorld");
	return 0;
}