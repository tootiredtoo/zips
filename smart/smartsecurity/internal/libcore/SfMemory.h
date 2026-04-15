/**
****************************************************************************************************
* @vd_noapi
* @file SfMemory.h
* @brief Security framework [SF] functions for working with memory
* @author Yurii Kryvokhata (y.kryvokhata@samsung.com)
* @date Created Mar 7, 2014 9:40
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_MEMORY_H_
#define _SF_MEMORY_H_

#include "SfConfig.h"
#include "SfTypes.h"
#include <memory.h>
#include <malloc.h>

#ifdef __cplusplus 
extern "C" {
#endif /* !__cplusplus */

#ifdef SF_BUILD_DEBUG
	#define SF_MEMORY_POISON
#endif /* !SF_BUILD_DEBUG */

/*
****************************************************************************************************
* @brief C++ operators new/delete
****************************************************************************************************
*/
#ifdef __cplusplus
    #define SF_NEW new
    #define SF_DELETE delete

    #define SF_NEW_ARRAY new
    #define SF_DELETE_ARRAY delete[]
#endif /* !__cplusplus */

#define sf_malloc(pObj, type, size) \
    pObj = (type*)malloc(size)

#define sf_free(pData) \
    if (pData) \
    { \
        free(pData); \
        pData = NULL; \
        malloc_trim(0); \
    }
    
/**
****************************************************************************************************
* @brief Copies the values of size bytes from the location pointed by pSource directly to the memory
*	block pointed by pDestination.
* @param [out] pDestination Pointer to the destination array where the content is to be copied,
*	type-casted to a pointer of type void*.
* @param [in] pSource Pointer to the source of data to be copied, type-casted to a pointer of type
*	const void*.
* @param [in] size Number of bytes to copy.
* @return pDestination is returned.
****************************************************************************************************
*/
SFLIB void* SFAPI sf_memcpy(void * pDestination, const void * pSource, size_t size);

/**
****************************************************************************************************
* @brief Partial case of the sf_memcpy function. Copies the first num characters of source to
*	pDestination. If the end of the pSource string (which is signaled by a null-character) is found
*	before num characters have been copied, pDestination is padded with zeros until a total of size
*	characters have been written to it. Ensure null byte terminating.
* @param [out] pDestination Pointer to the destination array where the content is to be copied,
*	type-casted to a pointer of type void*.
* @param [in] pSource Pointer to the source of data to be copied, type-casted to a pointer of type
*	const void*.
* @param [in] size Number of bytes to copy.
* @return pDestination is returned.
****************************************************************************************************
*/
SFLIB Char* sf_strncpy(Char* pDestination, const Char* pSource, size_t size);

#ifdef __cplusplus
}
#endif /* !__cplusplus */

#endif /* !_SF_MEMORY_H_ */
