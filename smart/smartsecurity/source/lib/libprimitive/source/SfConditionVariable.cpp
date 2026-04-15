/**
****************************************************************************************************
* @file SfConditionVariable.cpp
* @brief Security framework [SF] Condition variable primitive implementation
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Mar 20, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfConditionVariable.h"

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfConditionVariable::SfConditionVariable()
{
	pthread_cond_init( &m_handle, NULL );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfConditionVariable::~SfConditionVariable()
{
	pthread_cond_destroy( &m_handle );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfConditionVariable::NotifyOne()
{
	pthread_cond_signal( &m_handle );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfConditionVariable::NotifyAll()
{
	pthread_cond_broadcast( &m_handle );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfConditionVariable::Wait( SfMutex& mutex )
{
	pthread_cond_wait( &m_handle, &mutex.GetHandle() );
}
