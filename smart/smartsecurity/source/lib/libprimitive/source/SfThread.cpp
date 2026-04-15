/**
****************************************************************************************************
* @file SfThread.h
* @brief Security framework [SF] Thread mechanism implementation
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jul 25, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfThread.h"
#include "libcore/SfDebug.h"

#include <errno.h>
#include <string.h>
#include <signal.h>


/**
****************************************************************************************************
* @brief Functions
****************************************************************************************************
*/
static inline Char* GetErrorDescription( Int32 error )
{
    const Uint32 c_bufSize = 256;
    Char buf [ c_bufSize ] = { 0 };
    return strerror_r( error, buf, c_bufSize );
}

/**
****************************************************************************************************
* @brief Methods
****************************************************************************************************
*/
SfThread::SfThread( const std::string& threadName )
    : m_threadName ( threadName )
    , m_thread( 0 )
    , m_isRunning( FALSE )
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfThread::~SfThread()
{
    if ( m_isRunning )
    {
        SF_LOG_E( "(%s): destructor called on running thread;", m_threadName.c_str() );
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfThread::Start( SfThreadFunction function, void* arg )
{
    if ( m_isRunning )
    {
        SF_LOG_W( "(%s): thread is already running;", m_threadName.c_str() );
        return SF_STATUS_FAIL;
    }


    m_isRunning = TRUE;
    Int32 err = pthread_create( &m_thread, NULL, function, arg );
    if ( 0 != err )
    {
        m_isRunning = FALSE;
        SF_LOG_E( "(%s): pthread_create() failed, reason = %s;",
                  m_threadName.c_str(), GetErrorDescription( err ) );
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfThread::Cancel()
{
    if ( m_thread )
    {
        const Int32 err = pthread_cancel( m_thread );
        if ( 0 != err )
        {
            SF_LOG_E( "(%s):pthread_cancel() failed, reason = %s;",
                      m_threadName.c_str(), GetErrorDescription( err ) );
            return SF_STATUS_FAIL;
        }

        Stop();
        m_thread = 0;
    }
    else
    {
        SF_LOG_W( "thread was not created;" );
    }

    return SF_STATUS_OK;
}


SF_STATUS SfThread::Kill(int sig)
{
	int ret;
	SF_LOG_W("Send signal %d to thread id 0x%08lx", sig, m_thread);
	ret = pthread_kill(m_thread, sig);
	if (0 != ret) {
            SF_LOG_E( "(%s):pthread_kill() failed, reason = %s;",
                      m_threadName.c_str(), GetErrorDescription( ret ) );
            return SF_STATUS_FAIL;
	}

	return SF_STATUS_OK;
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfThread::Stop()
{
    if ( m_isRunning )
    {
        m_isRunning = FALSE;
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfThread::IsRunning() const
{
    return m_isRunning;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfThread::Join()
{
    if ( m_thread )
    {        
        const Int32 err = pthread_join( m_thread, NULL );
        if ( 0 != err )
        {
            SF_LOG_E( "(%s): pthread_join() failed, reason = %s;",
                      m_threadName.c_str(), GetErrorDescription( err ) );
            return SF_STATUS_FAIL;
        }
        m_thread = 0;
        Stop();
    }
    else
    {
        SF_LOG_W( "(%s): thread was not created;", m_threadName.c_str() );
    }

    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
const std::string& SfThread::GetThreadName() const
{
    return m_threadName;
}
