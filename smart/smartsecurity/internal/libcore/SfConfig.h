/**
****************************************************************************************************
* @vd_noapi
* @file SfConfig.h
* @brief Security framework [SF] common configurations file
* @author Yurii Kryvokhata (y.kryvokhata@samsung.com)
* @date Created Mar 4, 2014 16:07
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_CONFIG_H_
#define _SF_CONFIG_H_

#include "SfVersion.h"
#include "SfArch.h"
#include "SfSystem.h"
#include "SfLevel.h"
#include "SfBuild.h"

#if defined(SF_OS_LINUX) && defined(SF_LEVEL_KERNEL)
    #define SFLIB
	#define SFAPI
    #define SFCALL  asmlinkage
#elif defined(SF_OS_LINUX) && !defined(SF_LEVEL_KERNEL)
    #define SFLIB
#include <stddef.h>
#if !defined(SF_ARCH_X64) && !defined(SF_ARCH_ARM)
    #define SFAPI __attribute__((cdecl))
#else
    #define SFAPI
#endif /* !SF_ARCH_X64 */
    #define SFCALL
#elif defined(SF_OS_WINDOWS) && !defined(SF_LEVEL_KERNEL)
    #if defined(SF_LIB_EXPORT)
        #define SFAPI __cdecl
        #define SFLIB __declspec(dllexport)
    #elif defined(SF_LIB_IMPORT)
        #define  SFAPI __cdecl
        #define SFLIB __declspec(dllimport)
    #else
        #define SFAPI __cdecl
        #define SFLIB
    #endif
#else
#error Unsupported SFAPI configuration. Please, refer to 'SfConfig.h' file.
#endif

#endif /* !_SF_CONFIG_H_ */
