/**
****************************************************************************************************
* @file SfMemoryCommon.c
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

// local
#include "SfMemory.h"
#include "SfDebug.h"
#if defined(SF_LEVEL_USER)
    #include <string.h>
#endif // !SF_LEVEL_USER

// system
#ifdef SF_LEVEL_USER
#include <memory.h>
#endif /* SF_LEVEL_USER */

/*
****************************************************************************************************
*
****************************************************************************************************
*/
inline SFLIB void* SFAPI sf_memcpy( void* pDestination, const void* pSource, size_t size )
{
    return ( pDestination && pSource ) ? memcpy( pDestination, pSource, size ) : NULL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
inline SFLIB Char* SFAPI sf_strncpy( Char* pDestination, const Char* pSource, size_t size )
{
    Char* ret = NULL;
    if ( pDestination && pSource )
    {
        ret = strncpy( pDestination, pSource, size );

        if( size > 0)
            pDestination[size - 1] = '\0';
    }
    return ret;
}

