/**
****************************************************************************************************
* @vd_noapi
* @file SfRWLock.h
* @brief Security framework [SF] RW lock class
* @author Andrii Shelestov (a.shelestov)
* @date Created Sep 24, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_RWLOCK_H_
#define _SF_RWLOCK_H_

#include "libcore/SfCore.h"
#include <pthread.h>

//#define SF_RWLOCK_DEBUG // Uncomment for debug

/**
****************************************************************************************************
* @class SfRWLock
* @brief Read-write locker
* @todo	Refactor
****************************************************************************************************
*/
class SfRWLock
{
public: // functions
	
	/**
	************************************************************************************************
	* @brief Default constructor
	************************************************************************************************
	*/
	SfRWLock();

	/**
	************************************************************************************************
	* @brief Destructor
	************************************************************************************************
	*/
	~SfRWLock();

	/**
	************************************************************************************************
	* @brief 	Locks the object for synchronization for reading data
	* @return	SF_STATUS_OK when object was locked for reading, SF_STATUS_FAIL otherwise
	************************************************************************************************
	*/
	SF_STATUS	ReadLock();

	/**
	************************************************************************************************
	* @brief Have the same behavior as the ReadLock except, it does not wait for lock object instead
	*	return the status.
	* @return	SF_STATUS_OK when object was locked for reading, SF_STATUS_FAIL otherwise
	************************************************************************************************
	*/
	SF_STATUS	TryReadLock();

	/**
	************************************************************************************************
	* @brief	Locks the object for synchronization for writing data
	* @return	SF_STATUS_OK when object was locked for writing, SF_STATUS_FAIL otherwise
	************************************************************************************************
	*/
	SF_STATUS	WriteLock();

	/**
	************************************************************************************************
	* @brief Have the same behavior as the WriteLock except, it does not wait for lock object instead
	*	return the status.
	* @return	SF_STATUS_OK when object was locked for writing, SF_STATUS_FAIL otherwise
	************************************************************************************************
	*/
	SF_STATUS	TryWriteLock();

	/**
	************************************************************************************************
	* @brief Unlock the object
	************************************************************************************************
	*/
	SF_STATUS	Unlock();

	/**
	************************************************************************************************
	* @brief Lock the object
	* @note	 This method present to keep mutex-like interface
	************************************************************************************************
	*/
	SF_STATUS	Lock();

	/**
	************************************************************************************************
	* @todo Write comment
	* @note	 This method present to keep mutex-like interface
	************************************************************************************************
	*/
	SF_STATUS	TryLock();

	/**
	************************************************************************************************
	* @brief Extected usage for this variable is monitoring, if rwlock is inited correctly
	* @return	SF_STATUS_OK if object is valid, SF_STATUS_NOT_INITAILIZED otherwise
	************************************************************************************************
	*/
	SF_STATUS	GetCurrentStatus() const;

protected: // variables
	SF_STATUS	m_currentStatus; ///< pthread RW lock initialization status

private: // functions
	/**
	************************************************************************************************
	* @brief	Copy constructor blocked to prevent object copying
	* @param	[in] rwlock SfRWLock object
	************************************************************************************************
	*/
	SfRWLock( const SfRWLock& rwLock); // blocked

	/**
	************************************************************************************************
	* @brief	Assignment operator blocked to prevent object assignment
	* @param	[in] rwlock SfRWLock object
	************************************************************************************************
	*/
	const SfRWLock operator = (const SfRWLock& ); //blocked

private: // variables
	pthread_rwlock_t	m_handle; ///< pthread rwlock handle
};

#endif /* !_SF_RWLOCK_H_ */
