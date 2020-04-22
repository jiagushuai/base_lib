
#include <stdio.h>
#include <stdlib.h>
#include "zf_file_output.h"
#include "zf_log.h"

FILE *g_log_file = NULL;

static void file_output_callback(const zf_log_message *msg, void *arg)
{
	(void)arg;
	*msg->p = '\n';
	fwrite(msg->buf, msg->p - msg->buf + 1, 1, g_log_file);
	fflush(g_log_file);
}

static void file_output_close(void)
{
	fclose(g_log_file);
}

//非Unix系统
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(WIN32)
#include <direct.h>
#else
#include <unistd.h>
#endif
void ZF_FILE_OUTPUT_OPEN(const char *const log_path)
{
#ifdef WIN32
	fopen_s(&g_log_file, log_path, "a");
#else 
	g_log_file = fopen(log_path, "a");
#endif

	if (!g_log_file)
	{
		ZF_LOGW("Failed to open log file %s", log_path);
        const int MAXPATH=1024;
        char buffer[MAXPATH];
        getcwd(buffer, MAXPATH);
        ZF_LOGD("The current directory is: %s", buffer);
		return;
	}
	atexit(file_output_close);
	zf_log_set_output_v(ZF_LOG_PUT_STD, 0, file_output_callback);
}
