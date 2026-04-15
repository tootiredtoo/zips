/**
****************************************************************************************************
* @file SfStringUtilsTest.cpp
* @brief Security framework [SF] implementation: libprimitive is tested
* @author Viacheslav Vovchenko (v.vovchenko@samsung.com)
* @date November 27, 2014 18:00.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

// project
#include "libprimitive/SfStringUtils.h"
// third party
#include <gtest/gtest.h>
// namespaces
using namespace std;

/**
****************************************************************************************************
* @class SfStringUtils_TestSuite
* @brief C++  The thread-primitive's string utilites tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfStringUtils_TestSuite: public testing::Test
{
protected:

	/**
	****************************************************************************************************
	* @brief Called before the first test in this test case
	****************************************************************************************************
	*/
	static void SetUpTestCase()
	{
		//SfOpenDebuggerContext(NULL);
	}

	/**
	****************************************************************************************************
	* @brief Per-test set-up
	****************************************************************************************************
	*/
	virtual void SetUp()
	{

	}

	/**
	****************************************************************************************************
	* @brief Per-test tear-down
	****************************************************************************************************
	*/
	virtual void TearDown()
	{

	}
};

/**
***************************************************************************************************
//@sut      vdapi_SfStringUtilsUseTest_p SfStringUtils_TestSuite
//@brief    Test the operations with the strings
//@input    string
***************************************************************************************************
*/
TEST_F(SfStringUtils_TestSuite, vdapi_SfStringUtilsUseTest_p)
{
	string str;
	SfStringUtils::SplitString( str, 'A' );

	Uint8 u8 = 0;
	SfStringUtils::NumberToString( u8 );
	Int8 i8 = 0;
	SfStringUtils::NumberToString( i8 );
	Uint16 u16 = 0;
	SfStringUtils::NumberToString( u16 );
	Int16 i16 = 0;
	SfStringUtils::NumberToString( i16 );
	Uint32 u32 = 0;
	SfStringUtils::NumberToString( u32 );
	Int32 i32 = 0;
	SfStringUtils::NumberToString( i32 );
	Uint64 u64 = 0;
	SfStringUtils::NumberToString( u64 );
	Int64 i64 = 0;
	SfStringUtils::NumberToString( i64 );

	Char buffer[] = "0";
	SfStringUtils::Uint8FromString( buffer );
	SfStringUtils::Int8FromString( buffer );
	SfStringUtils::Uint16FromString( buffer );
	SfStringUtils::Int16FromString( buffer );
	SfStringUtils::Uint32FromString( buffer );
	SfStringUtils::Int32FromString( buffer );
	SfStringUtils::Uint64FromString( buffer );
	SfStringUtils::Int64FromString( buffer );

	size_t pos = 0;
	string str3;
	SfStringUtils::CopyBlock( str3, 'a', 'g', pos, str );
	str3 = "abcdefg";
	SfStringUtils::CopyBlock( str3, 'a', 'g', pos, str );
}
