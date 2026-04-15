/**
****************************************************************************************************
* @vd_noapi
* @file SfConditionVariable.h
* @brief Security framework [SF] Condition variable primitive
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Mar 20, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_CONDITION_VARIABLE_H_
#define _SF_CONDITION_VARIABLE_H_

#include "SfMutex.h"

/**
****************************************************************************************************
* @class SfConditionVariable
* @brief Condition variable primitive definition
****************************************************************************************************
*/
class SfConditionVariable
{
public: // functions
	/**
	************************************************************************************************
	* @brief	Default constructor
	************************************************************************************************
	*/
	SfConditionVariable();

	/**
	************************************************************************************************
	* @brief	Destructor
	************************************************************************************************
	*/
	~SfConditionVariable();

	/**
	************************************************************************************************
	* @brief 	Notify one consumer
	* @return 	void
	************************************************************************************************
	*/
	void NotifyOne();

	/**
	************************************************************************************************
	* @brief	Notify all consumers
	* @return	void
	************************************************************************************************
	*/
	void NotifyAll();

	/**
	************************************************************************************************
	* @biref 	Wait for condition
	* @param 	[in] mutex Mutex object
	* @return 	void
	************************************************************************************************
	*/
	void Wait( SfMutex& mutex );

protected: // lock operators

	/**
	************************************************************************************************
	* @brief	Copy constructor blocked to prevent object copying
	* @param	[in] conditionVariable Condition variable object
	************************************************************************************************
	*/
	SfConditionVariable( const SfConditionVariable& conditionVariable); // blocked

	/**
	************************************************************************************************
	* @brief	Assignment operator blocked to prevent object assignment
	* @param	[in] conditionVariable Condition variable object
	************************************************************************************************
	*/
	const SfConditionVariable& operator = ( const SfConditionVariable& ); // blocked

private: // variables

	pthread_cond_t		m_handle; ///< pthread condition variable handle

};

#endif /* !_SF_CONDITION_VARIABLE_H_ */
