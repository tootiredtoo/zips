/**
****************************************************************************************************
* @file SfRwLockTest.cpp
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
#include "libprimitive/SfRWLock.h"
// third party
#include <gtest/gtest.h>

/**
****************************************************************************************************
* @class SfRWLock_TestSuite
* @brief C++  The thread-primitive's r/w mutex tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfRWLock_TestSuite: public testing::Test
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
//@sut      vdapi_SfRwLockUseTest_p SfRWLock_TestSuite
//@brief    Test RW lock and Mutex implementation
//@input    SfRWLock
***************************************************************************************************
*/
TEST_F(SfRWLock_TestSuite, vdapi_SfRwLockUseTest_p)
{
	SfRWLock sfRWLock;

	EXPECT_TRUE( SF_SUCCESS( sfRWLock.GetCurrentStatus() ) );

	EXPECT_TRUE( SF_SUCCESS( sfRWLock.Lock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfRWLock.Unlock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfRWLock.TryLock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfRWLock.Unlock() ) );

	EXPECT_TRUE( SF_SUCCESS( sfRWLock.ReadLock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfRWLock.Unlock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfRWLock.TryReadLock() ) );
	EXPECT_TRUE( SF_SUCCESS( sfRWLock.Unlock() ) );
}
