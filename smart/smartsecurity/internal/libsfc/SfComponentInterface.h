/**
****************************************************************************************************
* @vd_noapi
* @file SfComponentInterface.h
* @brief Security framework [SF] operational interface to the components
* @author Maksym Koshel (m.koshel@samsung.com)
* @author Yurii Kryvokhata (y.kryvokhata@samsung.com)
* @date Created Aug 23, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_COMPONENT_INTERFACE_H_
#define _SF_COMPONENT_INTERFACE_H_

#include "SfState.h"

/**
****************************************************************************************************
* @def SF_COMPONENT_NAME_SIZE
* @brief Size of the component name
****************************************************************************************************
*/
#define	SF_COMPONENT_NAME_SIZE	32

/**
****************************************************************************************************
* @struct SfPluginInfo
* @brief Old SF plugin info structure
****************************************************************************************************
*/
typedef struct
{
	char			pluginName[SF_COMPONENT_NAME_SIZE]; ///< SF component name
	int				filterMask;	///< Filering mask
	unsigned int	componentPriority; ///< filtering priority
} SfPluginInfo;

/**
****************************************************************************************************
* @def SF_COMPONENT_INIT_FUNCTION_NAME
* @brief SF plugin initialization function name
****************************************************************************************************
*/
#define SF_COMPONENT_INIT_FUNCTION_NAME		"SFPInit"

/**
****************************************************************************************************
* @brief Function type of the SF plugin initialization function.
* @param [out] pInfo Pointer the structure to which will be provided information about plugin.
* @return Error code
****************************************************************************************************
*/
typedef SF_RET (*SfInitPluginInterface)(SfPluginInfo* pInfo);

/**
****************************************************************************************************
* @brief Function type of the SF plugin uninitialization function.
* @return Error code
****************************************************************************************************
*/
#define SF_COMPONENT_UNINIT_FUNCTION_NAME	"SFPDeinit"

/**
****************************************************************************************************
* @brief Function type of the SF plugin uninitialization function.
* @return Error code
****************************************************************************************************
*/
typedef void (*SfUninitPluginInterface)(void);

/**
****************************************************************************************************
* @brief Function type of the SF plugin scan file function.
* @return Error code
****************************************************************************************************
*/
#define SF_COMPONENT_SCAN_FUNCTION_NAME		"SFPScanFile"

/**
****************************************************************************************************
* @brief Function type of the SF plugin scan file function.
* @param [in] pRisk Pointer to the SF risk structure
* @return Error code
****************************************************************************************************
*/
typedef SF_RET (*SfScanFilePluginInterface)(SfRisk* pRisk);

/**
****************************************************************************************************
* @brief Function type of the SF plugin scan timeout callback function.
* @return Error code
****************************************************************************************************
*/
#define SF_COMPONENT_ONSCANTIMEOUT_FUNCTION_NAME	"SFPOnScanTimeout"

/**
****************************************************************************************************
* @brief Function type of the SF plugin scan timeout callback function.
* @return Error code
****************************************************************************************************
*/
typedef SF_RET (*SfOnScanTimeoutPluginInterface)(void);

/**
****************************************************************************************************
* @brief Function type of the SF plugin stop scan callback function.
* @return Error code
****************************************************************************************************
*/
#define SFP_COMPONENT_ONSTOPSCAN_FUNCTION_NAME	"SFPOnStopScan"

/**
****************************************************************************************************
* @brief Function type of the SF plugin stop scan callback function.
* @return Error code
****************************************************************************************************
*/
typedef SF_RET (*SfOnStopScanPluginInterface)(void);

/**
****************************************************************************************************
* @brief Function type of the SF plugin update function.
* @return Error code
****************************************************************************************************
*/
#define SFP_COMPONENT_UPDATE_FUNCTION_NAME	"SFPUpdate"

/**
****************************************************************************************************
* @brief Function type of the SF plugin update function.
* @return Error code
****************************************************************************************************
*/
typedef SF_RET (*SfUpdatePluginInterface)(void);

/**
****************************************************************************************************
* @struct SfComponentOperationContext
* @brief Old SF operation structure
****************************************************************************************************
*/
typedef struct
{
	void* pComponentHandle;
	SfInitPluginInterface pInit; ///< Pointer to the plugin initialization function
	SfUninitPluginInterface pUninit; ///< Pointer to the plugin uninitialization function
	SfScanFilePluginInterface pScan; ///< Pointer to the scan function
	SfOnScanTimeoutPluginInterface pScanTimeout; ///< Pointer to the scan timeout callback
	SfOnStopScanPluginInterface pOnStopScan; ///< Pointer Callback called 
	SfUpdatePluginInterface pUpdate;///< Pointer to the update interface
	SfPluginInfo info;
} SfComponentOperationContext;

#endif /* !_SF_COMPONENT_INTERFACE_H_ */
