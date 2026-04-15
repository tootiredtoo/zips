/**
****************************************************************************************************
* @file SfRWLock.h
* @brief Security framework [SF] RW lock mechanism implementation
* @author Andrii Shelestov (a.shelestov)
* @date Created Sep 24, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfRWLock.h"

#ifdef SF_RWLOCK_DEBUG
#include "libcore/SfDebug.h"
#endif

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfRWLock::SfRWLock()
{
	m_currentStatus =
		(pthread_rwlock_init( &m_handle, NULL ) == 0) ? SF_STATUS_OK : SF_STATUS_NOT_INITIALIZED;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::GetCurrentStatus() const
{
	return m_currentStatus;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfRWLock::~SfRWLock()
{
	pthread_rwlock_destroy( &m_handle );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::ReadLock()
{
	Int errCode = pthread_rwlock_rdlock( &m_handle );

#ifdef SF_RWLOCK_DEBUG
	SF_LOG_I("Return:%d;", errCode);
#endif /* !SF_RWLOCK_DEBUG */

	return ( errCode == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::TryReadLock()
{
	Int errCode = pthread_rwlock_tryrdlock( &m_handle );

#ifdef SF_RWLOCK_DEBUG
	SF_LOG_I("Return:%d;", errCode);
#endif /* !SF_RWLOCK_DEBUG */

	return ( errCode == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::Unlock()
{
	Int errCode = pthread_rwlock_unlock( &m_handle );

#ifdef SF_RWLOCK_DEBUG
	SF_LOG_I("Return:%d;", errCode);
#endif /* !SF_RWLOCK_DEBUG */

	return ( errCode == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::WriteLock()
{
	Int errCode = pthread_rwlock_wrlock( &m_handle );

#ifdef SF_RWLOCK_DEBUG
	SF_LOG_I("Return: %d;", errCode);
#endif /* !SF_RWLOCK_DEBUG */

	return ( errCode == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::TryWriteLock()
{
	Int errCode = pthread_rwlock_trywrlock( &m_handle );

#ifdef SF_RWLOCK_DEBUG
	SF_LOG_I("Return:%d;", errCode);
#endif /* !SF_RWLOCK_DEBUG */

	return ( errCode == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::Lock()
{
	return WriteLock();
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRWLock::TryLock()
{
	return TryWriteLock();
}
