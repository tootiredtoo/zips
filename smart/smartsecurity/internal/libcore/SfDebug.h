/**
****************************************************************************************************
* @vd_noapi
* @file SfDebug.h
* @brief Security framework [SF] debug implementation
* @author Yurii Kryvokhata (y.kryvokhata@samsung.com)
* @date Created Mar 4, 2014 12:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_DEBUG_H_
#define _SF_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif /* !__cplusplus */

/**
****************************************************************************************************
*
****************************************************************************************************
*/
#include "SfTypes.h"
#include "SfStatus.h"

#ifdef SF_LEVEL_USER
#include <string.h>
#include <dlog.h>
#endif

/**
****************************************************************************************************
* @brief Macros
****************************************************************************************************
*/
#define SF_GET_SYSTEM_ERROR(errno) \
({ \
    const Int bufferSize = 256; \
    Char buffer[bufferSize] = {0}; \
    strerror_r(errno, buffer, sizeof(buffer)); \
})


#ifdef USE_CONSOLE_LOG
void print_console_logs(const char *format, ...);
void create_console_log_event_loop(void);
void destroy_console_log_event_loop(void);
#else
	
#define create_console_log_event_loop()
#define destroy_console_log_event_loop()
	
#endif


#ifdef SF_BUILD_DEBUG
/**
****************************************************************************************************
* @brief Print message to the output stream
* @see SfLogHandler
****************************************************************************************************
*/
#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "smartsecurity"

#ifdef USE_CONSOLE_LOG
#ifdef SF_BIN_TAG
#define SF_LOG_I(format, arg...) ({					\
	LOGI("\033[36m" SF_BIN_TAG ": " format"\033[0m", ##arg);	        \
	print_console_logs("\033[36m" SF_BIN_TAG ": " format"\033[0m", ##arg);  \
	})
#define SF_LOG_W(format, arg...) ({					\
	LOGW("\033[33m" SF_BIN_TAG ": " format"\033[0m", ##arg);                \
	print_console_logs("\033[33m" SF_BIN_TAG ": " format"\033[0m", ##arg);  \
	})
#define SF_LOG_E(format, arg...) ({					\
	LOGE("\033[31m" SF_BIN_TAG ": " format"\033[0m", ##arg);                \
	print_console_logs("\033[31m" SF_BIN_TAG ": " format"\033[0m", ##arg);  \
	})
#else
#define SF_LOG_I(format, arg...) ({              \
	LOGI("\033[36m" format"\033[0m", ##arg); \
	print_console_logs("\033[36m" format"\033[0m", ##arg); \
	})
#define SF_LOG_W(format, arg...) ({                            \
	LOGW("\033[33m" format"\033[0m", ##arg);               \
	print_console_logs("\033[33m" format"\033[0m", ##arg); \
	})
#define SF_LOG_E(format, arg...) ({                            \
	LOGE("\033[31m" format"\033[0m", ##arg);               \
	print_console_logs("\033[31m" format"\033[0m", ##arg); \
	})
#endif
#else
#ifdef SF_BIN_TAG
#define SF_LOG_I(format, arg...) LOGI("\033[36m" SF_BIN_TAG ": " format"\033[0m", ##arg)
#define SF_LOG_W(format, arg...) LOGW("\033[33m" SF_BIN_TAG ": " format"\033[0m", ##arg)
#define SF_LOG_E(format, arg...) LOGE("\033[31m" SF_BIN_TAG ": " format"\033[0m", ##arg)
#else
#define SF_LOG_I(format, arg...) LOGI("\033[36m" format"\033[0m", ##arg)
#define SF_LOG_W(format, arg...) LOGW("\033[33m" format"\033[0m", ##arg)
#define SF_LOG_E(format, arg...) LOGE("\033[31m" format"\033[0m", ##arg)
#endif
#endif // USE_CONSOLE_LOG

#define SF_ASSERT(debugClass, condition, format, ...) \
    if(!(condition)) \
    { \
        SF_LOG_E( format, ##__VA_ARGS__ ); \
    }
#else
    #define SF_ASSERT(debugClass, condition, ...)
    #define SF_LOG(debugClass, debugLevel, ...)
    #define SF_LOG_I(...)
    #define SF_LOG_E(...)
    #define SF_LOG_W(...)
#endif /* ! SF_BUILD_DEBUG  */

#ifdef __cplusplus
}
#endif /* !__cplusplus */

#endif /* !_SF_DEBUG_H_ */
