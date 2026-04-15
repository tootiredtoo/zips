/**
****************************************************************************************************
* @vd_noapi
* @file SfLockGuard.h
* @brief Security framework [SF] Template class LockGuard implementation.
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Mar 22, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_LOCK_GUARD_H_
#define _SF_LOCK_GUARD_H_

#include <cstddef>

class SfMutex;

/**
****************************************************************************************************
* @class 	SfLockGuard
* @brief	Synchronize code scope by using SfMutex object
****************************************************************************************************
*/
class SfLockGuard
{
protected:
	/**
	************************************************************************************************
	* @brief	Default constructor
	************************************************************************************************
	*/
	SfLockGuard();

public: // func
	/**
	************************************************************************************************
	* @brief	Constructor
	* @param	[in] mutex Synchronization element
	************************************************************************************************
	*/
	explicit SfLockGuard( SfMutex& mutex );

	/**
	************************************************************************************************
	* @brief	Destructor
	************************************************************************************************
	*/
	~SfLockGuard();

private: // variables
	SfMutex* m_mutex; ///< pointer to the mutex
};

#endif /* !_SF_LOCK_GUARD_H_ */
