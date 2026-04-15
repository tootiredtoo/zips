/**
****************************************************************************************************
* @vd_noapi
* @file SfProtocolHeader.h
* @brief Security framework [SF] definition for kernel packet
* @author Maksym Koshel (m.koshel@samsung.com)
* @author Yurii Kryvokhata (y.kryvokhata@samsung.com)
* @date Created Apr 18, 2014 16:43
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_PROTOCOL_HEADER_H_
#define _SF_PROTOCOL_HEADER_H_

#include "libcore/SfCore.h"

/**
****************************************************************************************************
* @struct SfProtocolHeader
* @brief Protocol header used in all protocol related structures
****************************************************************************************************
*/
typedef struct __attribute__((__packed__))
{
	Uint size; ///< Owner structure size

	/**
	* @warning For type field should be used following enumerations: SF_OPERATION_TYPE,
	*	SF_PACKET_TYPE and SF_ENVIRONMENT_TYPE.
	* @see SF_PACKET_TYPE
	* @see SF_OPERATION_TYPE
	* @see SF_ENVIRONMENT_TYPE
	*/
	Uint type : 32;

} SfProtocolHeader;

#endif	/* _SF_PROTOCOL_HEADER_H_ */
