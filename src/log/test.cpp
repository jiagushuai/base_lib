#include "zf_file_output.h"
#include "zf_log.h"

#ifdef _DEBUG
#else
#define SDVERBOSE 
#endif
//#define SDVERBOSE

#define LOG_FILE    "print.log"

int main(int argc, char** argv)
{
#ifdef SDVERBOSE
	ZF_FILE_OUTPUT_OPEN(LOG_FILE);
	ZF_LOGD("==============执行这个语句才能生成文件，否则仅在控制台输出==============");
	ZF_LOGD("==============DEBUG模式下生成日志文件，在控制台输出==============", LOG_FILE);
#else
	ZF_LOGD("========Release模式下生成日志文件%s，在控制台输出==============", LOG_FILE);
#endif


	ZF_LOGD("==============生成日志文件==============");
	ZF_LOGD("==============%s==============", LOG_FILE);

    return 0;
}
