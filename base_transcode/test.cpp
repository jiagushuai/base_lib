#include "strnormalize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

	int main(int argc, char **argv)
	{
		str_normalize_init();
		const char *utf8 = "我是utf-8字符!";
		uint32_t utf8_len = strlen(utf8);
		uint32_t utf8buffer_len = utf8_len * 3 + 1;
		uint32_t gbkbuffer_len = utf8_len * 2 + 1;
		char *utf8buffer = (char *)malloc(utf8buffer_len);
		char *gbkbuffer = (char *)malloc(gbkbuffer_len);
		memset(utf8buffer, 0, utf8buffer_len);
		memset(gbkbuffer, 0, gbkbuffer_len);
		utf8_to_gbk(utf8, utf8_len, &gbkbuffer, &gbkbuffer_len);
		gbk_to_utf8(gbkbuffer, gbkbuffer_len, &utf8buffer, &utf8buffer_len);
		printf("utf8: %s<=>%d \t gbkbuffer: %s<=>%d\n", utf8, utf8_len, gbkbuffer, gbkbuffer_len);
		printf("gbk: %s<=>%d \t utf8buffer: %s<=>%d\n", gbkbuffer, gbkbuffer_len, utf8buffer, utf8buffer_len);
		free(utf8buffer);
		free(gbkbuffer);
		return 0;
	}