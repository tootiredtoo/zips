/**
****************************************************************************************************
* @file SfDebug.c
* @brief Security framework [SF]
* @author Oleksandr Biriukov (o.biryukov@samsung.com)
* @date Created May 09, 2025 11:40.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <glib.h>


#include "SfDebug.h"

#define BUF_SIZE                256

static GAsyncQueue* console_log_event_queue = NULL;
static pthread_mutex_t console_lock = PTHREAD_MUTEX_INITIALIZER;
static GThread *console_log_th = NULL;
static int console_log_thread_finished = 0;

typedef struct {
    int type;
    GString* log;
} console_msg;



static void print_log_console(int fd, char *buf)
{
        int ret;
        char output[1024];

        struct timespec tnow;

        if(buf == NULL)
                return;

        if(fd < 0)
        {
                SF_LOG_E("Invalid fd");
                return;
        }
        ret = clock_gettime(CLOCK_MONOTONIC, &tnow);
        snprintf(output, 1024, "%s\n", buf);
        ret = write(fd, output, strlen(output));

        if(ret < 0)
        {
            SF_LOG_E("Fail to write on console directly");
        }
	//        SF_LOG_I("[%ld.%6ld] completed", tnow.tv_sec, tnow.tv_nsec/1000);
}

static void* console_log_write_thread(void *data)
{
        console_msg *msg = NULL;
        pthread_mutex_lock(&console_lock);
        if (console_log_event_queue == NULL) {
                SF_LOG_E("console_log_event_queue is not ready");
                console_log_event_queue = g_async_queue_new();
        }
        int fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW);

        if(fd < 0) {
                SF_LOG_E("console device open fail");
                g_async_queue_unref(console_log_event_queue);
		pthread_mutex_unlock(&console_lock);
                return NULL;
        }

        pthread_mutex_unlock(&console_lock);
        while (!console_log_thread_finished) {
                msg = (console_msg*) g_async_queue_pop(console_log_event_queue);
                if (msg == NULL) {
                        SF_LOG_E("msg is null");
                }
                else {
                        print_log_console(fd, (char*) msg->log->str);
                        g_string_free(msg->log, TRUE);
                        free(msg);
                }
        }
        close(fd);
        g_async_queue_unref(console_log_event_queue);
        SF_LOG_I("Run console log event thread completed");

        return NULL;
}


void create_console_log_event_loop(void)
{
        console_log_th = g_thread_new("sfpmd_log", console_log_write_thread, NULL);

        if(console_log_th == NULL)
                SF_LOG_E("Failed to create new thread");
        else
                SF_LOG_I("Create console_log_write_thread thread successfully.");
}

void destroy_console_log_event_loop(void)
{
	if(console_log_th) {
		console_log_thread_finished = 1;
		print_console_logs("Finish console thread");
		g_thread_join(console_log_th);
	}
	SF_LOG_E("Finished console thread");
}

static int console_event_queue_push(console_msg* msg)
{
        if(!msg)
                return -1;

        pthread_mutex_lock(&console_lock);
        if (console_log_event_queue == NULL) {
                SF_LOG_E("console_log_event_queue is not ready");
                console_log_event_queue = g_async_queue_new();
        }
        pthread_mutex_unlock(&console_lock);
        g_async_queue_push(console_log_event_queue, (gpointer) msg);
        return 0;
}

static void print_console_log(char *buf)
{
        if(!buf)
                return;

        GString *msg = g_string_new(buf);
        GString *time_info = g_string_new("");

        g_string_append_printf(time_info, "[sfpmd] ");

        g_string_prepend(msg, time_info->str);
        g_string_free(time_info, TRUE);

        console_msg *msg_ = (console_msg *)malloc(sizeof(console_msg));
        msg_->type = 0;
        msg_->log = msg;
        console_event_queue_push(msg_);
}

void print_console_logs(const char *format, ...)
{
        char buf[BUF_SIZE] = {0, };
        va_list args;
        va_start(args, format);
        vsnprintf(buf, sizeof(buf) - 1, format, args);
        print_console_log(buf);
        va_end(args);
}

