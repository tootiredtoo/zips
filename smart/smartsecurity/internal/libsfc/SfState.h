/**
****************************************************************************************************
* @vd_noapi
* @file SfState.h
* @brief Security framework [SF] SF framework state structures declaration
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created Aug 23, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_STATE_H_
#define _SF_STATE_H_

/**
****************************************************************************************************
* @brief Old SF return result
* @todo Move to SF_STATUS
****************************************************************************************************
*/
#define SF_RET unsigned int

/**
****************************************************************************************************
* @brief Old SF risk grade enum
* @todo Change to kernel state machine when it will be verified on Tizen board
****************************************************************************************************
*/
typedef enum
{
	SF_RISK_GRADE_NULL = 0, ///< NULL Grade
	SF_RISK_GRADE_SAFE = 1, ///< The state of the checked resource is safe
	SF_RISK_GRADE_WARNING = 2, ///< Warning state
	SF_RISK_GRADE_CRITICAL = 3, ///< This is malware
	SF_RISK_GRADE_MAX = SF_RISK_GRADE_CRITICAL
} SF_RISK_GRADE;

/**
****************************************************************************************************
* @def SF_RISK_DESCRIPTION_SIZE
* @brief Size in bytes of the description field in the SfRisk structure
****************************************************************************************************
*/
#define	SF_RISK_DESCRIPTION_SIZE	1024

/**
****************************************************************************************************
* @def SF_RESOURCE_NAME_SIZE
* @brief Size of the resource name
****************************************************************************************************
*/
#define SF_RESOURCE_NAME_SIZE		4096

/**
****************************************************************************************************
* @brief Old Security Framework risk information
* @todo To change this structure to SfResource when kernel state machine will be verified
* @warrnig This structure takes a lot of memory. Be carefull while allocating it on a stack.
****************************************************************************************************
*/
typedef struct
{
	SF_RISK_GRADE	grade; ///< Returned risks grade. Updated by a plugin
	char resourceName[SF_RESOURCE_NAME_SIZE]; ///< Resource name to be verified
	char resourceDescription[SF_RISK_DESCRIPTION_SIZE]; ///< Resource description
} SfRisk;

#endif /* _SF_STATE_H_ */
