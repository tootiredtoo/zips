/**
****************************************************************************************************
* @file SfTime.c
* @brief Security framework [SF] time functions definitions
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Mar 6, 2014 9:00
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

// local
#include "SfTime.h"
#include <stdio.h>

#if defined(SF_OS_LINUX) && !defined(SF_LEVEL_KERNEL)
#include <time.h>
#include <unistd.h>
#endif

#if defined(SF_LEVEL_USER)

// system
#include <time.h>
#include <unistd.h>

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint64 SFAPI SfGetSystemTimeUsec(void)
{
#if defined(SF_OS_WINDOWS)
    return GetTickCount() * 1000;
#else
    struct timespec t;
    clock_gettime( CLOCK_MONOTONIC, &t );
    return ((Uint64)t.tv_sec) * 1000000L + ((Uint64)t.tv_nsec) / 1000;
#endif	//!	SF_OS_WINDOWS
}

#else
/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint64 SFAPI SfGetSystemTimeUsec(void)
{
    Uint64 usecTime = 0;
    Uint32 rem = 0;
    struct timespec timeOfDay;

    getnstimeofday( &timeOfDay );
    usecTime  = (Uint64)timeOfDay.tv_sec * 1000000L;
    usecTime += div_u64_rem( (Uint64)timeOfDay.tv_nsec, 1000, &rem );
    return usecTime;
}

#endif /* !SF_LEVEL_USER */

#if defined(SF_LEVEL_KERNEL)
// system
#include <linux/time.h>
#include <linux/delay.h>
#endif

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SFAPI SfSleepMs(Ulong timeMs)
{
#if defined(SF_OS_WINDOWS)
    Sleep(timeMs);
#elif defined (SF_OS_LINUX) && defined(SF_LEVEL_KERNEL)
    msleep(timeMs);
#elif defined (SF_OS_LINUX) && !defined(SF_LEVEL_KERNEL)
    /**
    * @todo: To change it to microseconds since there is no standard API function for miliseconds
    */
    usleep(timeMs * 1000);
#endif
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SFAPI SfParseTimeStructure(SfTime* pTime, Uint64 rsec)
{
#if defined(SF_LEVEL_KERNEL)
    Uint32 sec = 0, min = 0, hours = 0;

    rsec = div_u64_rem( rsec, 1000, &pTime->usec );
    rsec = div_u64_rem( rsec, 1000, &pTime->msec );
    rsec = div_u64_rem( rsec, 60, &sec );
    rsec = div_u64_rem( rsec, 60, &min );
    rsec = div_u64_rem( rsec, 24, &hours );

    pTime->sec     = sec;
    pTime->minutes = min;
    pTime->hours   = hours;
    pTime->days    = (Uint32)rsec;
#else
    pTime->usec = (unsigned long)(rsec % 1000);
    rsec /= 1000;
    pTime->msec = (unsigned long)(rsec % 1000);
    rsec /= 1000;
    pTime->sec = rsec % 60;
    rsec /= 60;
    pTime->minutes = rsec % 60;
    rsec /= 60;
    pTime->hours	= rsec % 24;
    rsec /= 24;
    pTime->days = (Uint32)rsec;
#endif // SF_LEVEL_KERNEL
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
const char* SfGetUsSysTimeAsString( char* buff,int bsize )
{
    time_t nowtime;
    struct timespec tv;
    struct tm  struct_time;

    if( buff == NULL || bsize < 1)
        return NULL;

    clock_gettime(CLOCK_REALTIME, &tv);
    nowtime = tv.tv_sec;
    struct_time = *gmtime_r(&nowtime, &struct_time);
    snprintf(buff,bsize,"%02d%02d%02d%ld", struct_time.tm_hour, struct_time.tm_min, struct_time.tm_sec, tv.tv_nsec/1000 );
    buff[bsize - 1] = '\0';
    return buff;
}


