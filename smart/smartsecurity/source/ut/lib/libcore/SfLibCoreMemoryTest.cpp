/**
****************************************************************************************************
* @file SfLibCoreMemoryTest.cpp
* @brief Security framework [SF] implementation: libcore is tested
* @author Viacheslav Vovchenko (v.vovchenko@samsung.com)
* @date November 29, 2014 18:00.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

// project
#include "libcore/SfCore.h"
#include "libcore/SfDebug.h"
// third party
#include <gtest/gtest.h>

/**
****************************************************************************************************
* @class SfCoreMemory_TestSuite
* @brief C++  File operations tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfCoreMemory_TestSuite: public testing::Test
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

protected:

	static const Int32 	IntTstVal 		= 	0xff;//!< used to test as value
	static const Uint32 UintTstVal 		= 	0xff;//!< used to test as size
	static const Int32 	PoisonTstVal 	=	0xaf;//!< used to test strings
	static const Char  	CharTstVal		=	'S'; //!< used to test strings
};

/**
***************************************************************************************************
//@sut      vdapi_SfMemcpyTest_p SfCoreMemory_TestSuite
//@brief    Check copies of memory positive Test
//@input    null
***************************************************************************************************
*/
TEST_F(SfCoreMemory_TestSuite, vdapi_SfMemcpyTest_p)
{
	Uchar arrSrc[UintTstVal]  = { PoisonTstVal };

	EXPECT_TRUE( NULL == sf_memcpy(NULL, 0, 0) );
	EXPECT_TRUE( NULL == sf_memcpy(NULL, 0, UintTstVal) );
	EXPECT_TRUE( NULL == sf_memcpy(NULL, arrSrc, 0) );
	EXPECT_TRUE( NULL == sf_memcpy(NULL, arrSrc, UintTstVal) );
}
/**
***************************************************************************************************
//@sut      vdapi_SfStrncpyTest_p SfCoreMemory_TestSuite
//@brief    Check copies of strings positive Test
//@input    null
***************************************************************************************************
*/
TEST_F(SfCoreMemory_TestSuite, vdapi_SfStrncpyTest_p)
{
	Char strSrc[UintTstVal]  = { CharTstVal };

	EXPECT_TRUE( NULL == sf_strncpy(NULL, 0, 0) );
	EXPECT_TRUE( NULL == sf_strncpy(NULL, 0, UintTstVal) );
	EXPECT_TRUE( NULL == sf_strncpy(NULL, strSrc, 0) );
	EXPECT_TRUE( NULL == sf_strncpy(NULL, strSrc, UintTstVal) );
}

 /**
 ***************************************************************************************************
 //@sut      vdapi_SfOtherTest_p SfCoreMemory_TestSuite
 //@brief    Check various sequencies positive Test
 //@input    Char Value
 ***************************************************************************************************
 */
TEST_F(SfCoreMemory_TestSuite, vdapi_SfOtherTest_p)
{
	Char a1 = 'a';
	Char a2 = 'b';
	EXPECT_TRUE( NULL != sf_memcpy(&a1, &a2, sizeof(Char)) );
}
