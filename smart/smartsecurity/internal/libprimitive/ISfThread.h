/**
****************************************************************************************************
* @vd_noapi
* @file ISfThraed.h
* @brief Security framework [SF] interface
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jun 19, 2014 09:07
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _I_SF_THREAD_H_
#define _I_SF_THREAD_H_

// project
#include "libprimitive/SfThread.h"

/**
****************************************************************************************************
*
****************************************************************************************************
*/
template < typename Type >
class ISfThread
{
public: // methods
    ISfThread( const std::string& threadName )
        : m_thread( threadName )
    {
    }

    virtual ~ISfThread()
    {
    }

    virtual SF_STATUS Run()
    {
        return m_thread.Start( Type::StartThread, (void*)this );
    }

    virtual SF_STATUS Join()
    {
        return m_thread.Join();
    }

    virtual Bool IsRunning() const
    {
        return m_thread.IsRunning();
    }

    virtual void Stop()
    {
        return m_thread.Stop();
    }

protected: // methods
    virtual void ThreadFunction() = 0;

    static void* StartThread( void* pContext )
    {
        static_cast < Type* > ( pContext )->ThreadFunction();
        return NULL;
    }

protected: // members
    SfThread m_thread;

}; // class ISfThread

#endif /* _I_SF_THREAD_H_ */
