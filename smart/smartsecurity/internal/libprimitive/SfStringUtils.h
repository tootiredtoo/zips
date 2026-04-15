/**
****************************************************************************************************
* @vd_noapi
* @file SfStringUtils.h
* @brief Security framework [SF] Declaration of the functions to operate with strings
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Jul 25, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_STRING_UTILS_H_
#define _SF_STRING_UTILS_H_

#include "libcore/SfCore.h"

#include <string>
#include <vector>

/**
****************************************************************************************************
* @typedef	SfStringUtils
* @brief 	String utilities namespace
* @todo 	Refactor
****************************************************************************************************
*/
namespace SfStringUtils
{

/**
****************************************************************************************************
* @typedef	SfStringVector
* @brief 	String vector
****************************************************************************************************
*/
typedef std::vector< std::string >	SfStringVector;

/**
****************************************************************************************************
* @typedef 	SfByteVector
* @brief 	Byte vector
****************************************************************************************************
*/
typedef std::vector< Uint8 >		SfByteVector;

/**
****************************************************************************************************
* @brief 	Split strings
* @param	[in] str input string
* @param	[out] items processed string tokens
* @param	[in] delim key symbol
* @return	void
****************************************************************************************************
*/
void SplitString( const std::string& str, SfStringVector& items, Char delim );

/**
****************************************************************************************************
* @brief Write comment
* @param	[in] str input string
* @param	[in] delim key symbol
* @return	Processed string tokens in SfStringVector container
****************************************************************************************************
*/
SfStringVector	SplitString( const std::string& str, Char delim );

#if !defined(SF_OS_WINDOWS)

/**
****************************************************************************************************
* @brief Convert unsigned 8-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Uint8 	value );

/**
****************************************************************************************************
* @brief Convert signed 8-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Int8 	value );

/**
****************************************************************************************************
* @brief Convert unsigned 16-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Uint16 value );

/**
****************************************************************************************************
* @brief Convert signed 16-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Int16 	value );

/**
****************************************************************************************************
* @brief Convert unsigned 32-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Uint32 value );

/**
****************************************************************************************************
* @brief Convert signed 32-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Int32 	value );

/**
****************************************************************************************************
* @brief Convert unsigned 64-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Uint64 value );

/**
****************************************************************************************************
* @brief Convert signed 64-bit number to string
* @param	[in] value number to convert
* @return	Number in string representation
****************************************************************************************************
*/
std::string NumberToString( Int64 	value );

/**
****************************************************************************************************
* @brief Convert string to unsigned 8-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Uint8 Uint8FromString( const Char* buffer );

/**
****************************************************************************************************
* @brief Convert string to signed 8-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Int8 Int8FromString( const Char* buffer );

/**
****************************************************************************************************
* @brief Convert string to unsigned 16-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Uint16 Uint16FromString( const Char* buffer );

/**
****************************************************************************************************
* @brief Convert string to signed 16-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Int16 Int16FromString( const Char* buffer );

/**
****************************************************************************************************
* @brief Convert string to unsigned 32-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Uint32 Uint32FromString( const Char* buffer );

/**
****************************************************************************************************
* @brief Convert string to signed 32-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Int32 Int32FromString( const Char* buffer );

/**
****************************************************************************************************
* @brief Convert string to unsigned 64-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Uint64 Uint64FromString( const Char* buffer );

/**
****************************************************************************************************
* @brief Convert string to signed 64-bit number
* @param	[in] buffer string to convert
* @return	Number
****************************************************************************************************
*/
Int64 Int64FromString( const Char* buffer );

#endif /* !SF_WINDOWS */

/**
****************************************************************************************************
* @brief    copy data from open symbol(like '{','[') to close symbol(like '}','[')
* @param    [in] @source - source data;
* @param    [in] @openSymbol - opening symbol (like '{','[');
* @param    [in] @closeSymbol - closing symbol (like '}',']');
* @param    [in/out] @position - position of opening symbol(like '{','[');
*           returns @position of closing(like '}',']') symbol;
* @param    [in/out] @copiedData - copied data from @source string;
* @return   return SF_STATUS_OK if ok else SF_STATUS_FAIL;
****************************************************************************************************
*/
SF_STATUS CopyBlock( const std::string& source, Char openSymbol, Char closeSymbol,
                     size_t& position, std::string& copiedData );

/**
****************************************************************************************************
* @brief    copy data from @position to first one of @symbols
* @param    [in] @source - source data;
* @param    [in] @symbols - terminating symbols;
* @param    [in/out] @position - start position; returns position of first one of @symbols;
* @param    [in/out] @copiedData - copied data from source string;
* @return   return SF_STATUS_OK if ok else SF_STATUS_FAIL;
****************************************************************************************************
*/
SF_STATUS CopyBlock( const std::string& source, const std::string& symbols,
                     size_t& position, std::string& copiedData );

} /* !SfStringUtils */

#endif /* !_SF_STRING_UTILS_H_ */
