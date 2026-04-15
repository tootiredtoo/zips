/**
****************************************************************************************************
* @file SfStringUtils.h
* @brief Security framework [SF] Functions implementation to operate with strings
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Jul 25, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfStringUtils.h"
#include "libcore/SfDebug.h"

#include <cstdio>
#include <sstream>
#include <iomanip>
#ifndef __STDC_FORMAT_MACROS
    #define __STDC_FORMAT_MACROS
#endif /* !__STDC_FORMAT_MACROS */

#if !defined(SF_OS_WINDOWS)
    #include <inttypes.h>
#endif /* !SF_OS_WINDOWS */

namespace SfStringUtils
{

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SplitString( const std::string& str, SfStringVector& items, Char delim )
{
    std::istringstream iss( str );
    std::string currToken;

    while ( std::getline( iss, currToken, delim ) )
        items.push_back( currToken );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfStringVector SplitString( const std::string& str, Char delim )
{
    SfStringVector items;
    SplitString( str, items, delim );
    return items;
}

#if !defined(SF_WINDOWS)
/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Uint8 value )
{
    const Uint8 c_bufSize = 10;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRIu8, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Int8 value )
{
    const Uint8 c_bufSize = 10;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRId8, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Uint16 value )
{
    const Uint8 c_bufSize = 12;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRIu16, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Int16 value )
{
    const Uint8 c_bufSize = 12;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRId16, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Uint32 value )
{
    const Uint8 c_bufSize = 14;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRIu32, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Int32 value )
{
    const Uint8 c_bufSize = 14;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRId32, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Uint64 value )
{
    const Uint8 c_bufSize = 24;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRIu64, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string NumberToString( Int64 value )
{
    const Uint8 c_bufSize = 24;
    char buf [ c_bufSize ];
    snprintf( buf, c_bufSize, "%" PRId64, value );
    return buf;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint8 Uint8FromString( const Char* buffer )
{
    Uint8 res = 0;
    sscanf( buffer, "%" SCNu8, &res );
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Int8 Int8FromString( const Char* buffer )
{
    Int8 res = 0;
    sscanf( buffer, "%" SCNd8, &res );
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint16 Uint16FromString( const Char* buffer )
{
    Uint16 res = 0;
    sscanf( buffer, "%" SCNu16, &res );
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Int16 Int16FromString( const Char* buffer )
{
    Int16 res = 0;
    sscanf( buffer, "%" SCNd16, &res );
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint32 Uint32FromString( const Char* buffer )
{
    Uint32 res = 0;
    sscanf( buffer, "%" SCNu32, &res );
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Int32 Int32FromString( const Char* buffer )
{
    Int32 res = 0;
    sscanf( buffer, "%" SCNd32, &res );
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Uint64 Uint64FromString( const Char* buffer )
{
    Uint64 res = 0;
    sscanf( buffer, "%" SCNu64, &res );
    return res;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Int64 Int64FromString( const Char* buffer )
{
    Int64 res = 0;
    sscanf( buffer, "%" SCNd64, &res );
    return res;
}
#endif // SF_WINDOWS

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS CopyBlock( const std::string& source, Char openSymbol, Char closeSymbol,
                     size_t& position, std::string& copiedData )
{
    Uint32 braceCounter = 1;
    size_t startPosition = position + 1, size = 0;
    for ( ; startPosition < source.size(); ++startPosition )
    {
        if ( source[ startPosition ] == openSymbol )
        {
            braceCounter += 1;
        }

        if ( source[ startPosition ] == closeSymbol )
        {
            braceCounter -= 1;
            if ( 0 == braceCounter )
            {
                size = startPosition - position + 1;
                break;
            }
        }
    }

    if ( 0 == size )
    {
        SF_LOG_E( "wrong data, symbol [%c] not found;", closeSymbol );
        return SF_STATUS_FAIL;
    }

    copiedData = source.substr( position, size );
    position += size;
    return SF_STATUS_OK;
}

SF_STATUS CopyBlock( const std::string& source, const std::string& symbols,
                     size_t& position, std::string& copiedData )
{
    const size_t startPosition = source.find_first_of( symbols, position );
    if ( startPosition == std::string::npos )
    {
        SF_LOG_E( "symbols [%s] not found;", symbols.c_str() );
        return SF_STATUS_FAIL;
    }

    copiedData = source.substr( position, startPosition - position );
    position += startPosition - position + 1;
    return SF_STATUS_OK;
}

} /* !SfStringUtils */
