/**
****************************************************************************************************
* @vd_noapi
* @file SfMutex.h
* @brief Security framework [SF] Mutex class definition
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created May 14, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_MUTEX_H_
#define _SF_MUTEX_H_

#include "libcore/SfCore.h"
#include <pthread.h>

/**
****************************************************************************************************
* @class SfMutex
* @brief C++ mutex primitive implementation
****************************************************************************************************
*/
class SfMutex
{
public:
    /**
    ************************************************************************************************
    * @enum     SF_MUTEX_TYPE
    * @brief    Define mutex types
    * @param    [in] type Mutex type
    ************************************************************************************************
    */
    typedef enum
    {
        SF_MUTEX_TYPE_NORMAL = 0, ///< None recursive mutex
        SF_MUTEX_TYPE_RECURSIVE = 1 ///< Recursive mutex
    } SF_MUTEX_TYPE;

public: // interfaces
    /**
    ************************************************************************************************
    * @brief    Constructor of the Mutex object that will craete recursive mutex by deafult.
    * @param    [in] type Mutex type
    ************************************************************************************************
    */
    SfMutex(SF_MUTEX_TYPE type = SF_MUTEX_TYPE_RECURSIVE);

    /**
    ************************************************************************************************
    * @brief    Destructor
    ************************************************************************************************
    */
    ~SfMutex();

    /**
    ************************************************************************************************
    * @brief    Lock the given mutex
    * @return   SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Lock();

    /**
    ************************************************************************************************
    * @brief    The same behaviour as in the Lock() except, that it does not block the calling
    *   thread if the mutex is already locked by another thread
    * @return   SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS TryLock();

    /**
    ************************************************************************************************
    * @brief    Unlock the given mutex
    * @return   SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Unlock();

    /**
    ************************************************************************************************
    * @brief    Get pthread handle. It is neccessary to implement condition variable withuot
    *   friend class.
    * @return   SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    pthread_mutex_t& GetHandle();

private:

    pthread_mutex_t m_handle; ///< pthread mutex handle

protected: // lock operators
    /**
    ************************************************************************************************
    * @brief    Copy constructor blocked to prevent object copying
    * @param    [in] mutex mutex object
    ************************************************************************************************
    */
    SfMutex( const SfMutex& mutex ); // blocked

    /**
    ************************************************************************************************
    * @brief    Assignment operator blocked to prevent object assignment
    * @param    [in] mutex mutex object
    ************************************************************************************************
    */
    const SfMutex& operator = ( const SfMutex& mutex ); // blocked
};

#endif /* !_SF_MUTEX_H_ */
