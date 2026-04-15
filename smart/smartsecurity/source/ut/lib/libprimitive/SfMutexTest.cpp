/**
****************************************************************************************************
* @file SfMutexTest.cpp
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
#include "libprimitive/SfMutex.h"
// third party
#include <gtest/gtest.h>

/**
****************************************************************************************************
* @class SfMutex_TestSuite
* @brief C++  The thread-primitive's mutex tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfMutex_TestSuite: public testing::Test
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
//@sut      vdapi_SfMutexUseTest_p SfMutex_TestSuite
//@brief    Test mutex implementation Positive Test
//@input    Mutex
***************************************************************************************************
*/
TEST_F(SfMutex_TestSuite, vdapi_SfMutexUseTest_p)
{
	SfMutex sfMutex;
	//Simple Lock/Unlock
	EXPECT_TRUE( SF_SUCCESS( sfMutex.Lock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfMutex.Unlock() ) );
	//Not waiting TryLock/Unlock
	EXPECT_TRUE( SF_SUCCESS( sfMutex.TryLock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfMutex.Unlock() ) );
}
