/**
****************************************************************************************************
* @vd_noapi
* @file SfCore.h
* @brief Security framework [SF]
* @author Yurii Kryvokhata (y.kryvokhata@samsung.com)
* @date Created Mar 4, 2014 11:10
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_CORE_H_
#define _SF_CORE_H_

#ifdef __cplusplus 
extern "C" {
#endif /* !__cplusplus */

#include "SfVersion.h"
#include "SfConfig.h"
#include "SfTypes.h"
#include "SfDebug.h"
#include "SfStatus.h"
#include "SfValidator.h"
#include "SfTime.h"
#include "SfMemory.h"

/*CPP APIs*/
#include "SfEnum.h"

#ifdef __cplusplus
}
#endif /* !__cplusplus */

#ifdef __cplusplus
extern "C"
{
#endif /* !__cplusplus */

/**
****************************************************************************************************
* @brief This struct containt core context information
****************************************************************************************************
*/
typedef struct
{
    SfContextHeader	header; ///< Header of the context structure
    Uint64			startTime; ///< Timestamp when the context created
} SfCoreContext;

#ifdef __cplusplus
}
#endif /* !__cplusplus */

#endif /* !_SF_CORE_H_ */
