/**
****************************************************************************************************
* @file SfLockGuard.cpp
* @brief Security framework [SF] Lock guard mechanism implementation
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Mar 22, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfLockGuard.h"
#include "SfMutex.h"

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfLockGuard::SfLockGuard( SfMutex& mutex )
	: m_mutex( &mutex )
{
	m_mutex->Lock();
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfLockGuard::~SfLockGuard()
{
	if ( m_mutex )
	{
		m_mutex->Unlock();
	}
}
