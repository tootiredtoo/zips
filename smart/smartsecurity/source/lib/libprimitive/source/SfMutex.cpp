/**
****************************************************************************************************
* @file SfMutex.cpp
* @brief Security framework [SF] Mutex class implementation
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created May 14, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfMutex.h"

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfMutex::SfMutex(SF_MUTEX_TYPE type)
{
	pthread_mutexattr_t attr;
	pthread_mutexattr_init( &attr );

	pthread_mutexattr_settype( &attr,
		(type == SF_MUTEX_TYPE_RECURSIVE) ? PTHREAD_MUTEX_RECURSIVE : PTHREAD_MUTEX_NORMAL );

	pthread_mutex_init( &m_handle, &attr );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfMutex::~SfMutex()
{
	pthread_mutex_destroy( &m_handle );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
pthread_mutex_t& SfMutex::GetHandle()
{
	return m_handle;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMutex::Lock()
{
	return ( pthread_mutex_lock( &m_handle ) == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMutex::TryLock()
{
	return ( pthread_mutex_trylock( &m_handle ) == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMutex::Unlock()
{
    return ( pthread_mutex_unlock( &m_handle ) == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}