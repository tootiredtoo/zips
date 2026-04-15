/**
****************************************************************************************************
* @vd_noapi
* @file SfThread.h
* @brief Security framework [SF] Thread class definition.
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Jul 25, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_THREAD_H_
#define _SF_THREAD_H_

#include "libcore/SfCore.h"
#include <pthread.h>
#include <string>

/**
****************************************************************************************************
* @class SfThread
* @brief C++ thread primitive implementation
* @todo	Refactor SfThread class
****************************************************************************************************
*/
class SfThread
{
public:
    /**
    ************************************************************************************************
    * @typedef	SfThreadFunction
    * @brief	Function type for the thread worker
    * @param	[in] arg pointer to an arguments of the function to be called in the thread
    * @return	void*
    ************************************************************************************************
    */
    typedef void* ( *SfThreadFunction )( void* arg );

public: // functions

    /**
    ************************************************************************************************
    * @brief	Constructor of the thread object
    ************************************************************************************************
    */
    SfThread( const std::string& threadName );

    /**
    ************************************************************************************************
    * @brief	Destructor
    ************************************************************************************************
    */
    ~SfThread();

    /**
    ************************************************************************************************
    * @brief	Start thread
    * @param	[in] function Pointer to the thread worker
    * @param	[in] arg Arguments that will be thrown to thread worker
    * @return	SF_STATUS_OK on success, SF_STATUS_FAILED otherwise
    ************************************************************************************************
    */
    SF_STATUS	Start( SfThreadFunction function, void* arg );

    /**
    ************************************************************************************************
    * @brief	Force destroy of the thread object
    ************************************************************************************************
    */
    SF_STATUS 	Cancel();

    /**
    ************************************************************************************************
    * @brief	Send signal to thread
    * @param	[in] sig - signal to send
    ************************************************************************************************
    */
    SF_STATUS   Kill(int sig);

    /**
    ************************************************************************************************
    * @brief	Stop thread
    ************************************************************************************************
    */
    void Stop();

    /**
    ************************************************************************************************
    * @brief	Is thread running
    * @return	TRUE if thread is running, FALSE otherwise
    ************************************************************************************************
    */
    Bool	IsRunning() const;

    /**
    ************************************************************************************************
    * @brief	Wait for thread will be finished
    * @return	SF_STATUS_OK on success, SF_STATUS_FAILED otherwise
    ************************************************************************************************
    */
    SF_STATUS	Join();

    /**
    ************************************************************************************************
    * @brief    Get thread name
    * @return   @m_threadName
    ************************************************************************************************
    */
    const std::string& GetThreadName() const;

protected: // lock operators
    /**
    ************************************************************************************************
    * @brief	Copy constructor blocked to prevent object copying
    * @param	[in] thread Thread object
    ************************************************************************************************
    */
    SfThread( const SfThread& thread ); // blocked

    /**
    ************************************************************************************************
    * @brief	Assignment operator blocked to prevent object assignment
    * @param	[in] thread Thread object
    ************************************************************************************************
    */
    const SfThread& operator=( const SfThread& thread ); // blocked

private: // members

    std::string m_threadName;   ///< thread name
    pthread_t	m_thread;       ///< pthread handle
    Bool		m_isRunning;    ///< Flag that indicate while thread is running or not
};

#endif /* !_SF_THREAD_H_ */
