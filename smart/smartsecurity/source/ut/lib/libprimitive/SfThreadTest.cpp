/**
****************************************************************************************************
* @file SfThreadTest.cpp
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
#include "libprimitive/SfThread.h"
// third party
#include <gtest/gtest.h>

/**
****************************************************************************************************
* @class SfThread_TestSuite
* @brief C++  The thread-primitive's thread tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfThread_TestSuite: public testing::Test
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

	/**
	****************************************************************************************************
	* @brief Function is executes a thread
	* @param [in] Not used
	* @return NULL Not used
	****************************************************************************************************
	*/
	static void* ThreadFunc( void* pContext )
	{
		return NULL;
	}
};

 /**
 ***************************************************************************************************
 //@sut      vdapi_SfThreadUseTest_p SfThread_TestSuite
 //@brief    Test the operations with the threads Positive Test
 //@input    NULL
 ***************************************************************************************************
 */
TEST_F(SfThread_TestSuite, vdapi_SfThreadUseTest_p)
{
	const char* strName[] = {"Thread1", "Thread2"};
	SfThread sfThread1( strName[0] ),
			 sfThread2( strName[1] );

	EXPECT_STREQ( strName[0], sfThread1.GetThreadName().c_str());
	EXPECT_STREQ( strName[1], sfThread2.GetThreadName().c_str());
	//Not waiting thread
	EXPECT_TRUE( SF_SUCCESS( sfThread1.Start( ThreadFunc, NULL) ) );
	EXPECT_TRUE( TRUE == sfThread1.IsRunning() );
	sfThread1.Stop();
	EXPECT_TRUE( FALSE == sfThread1.IsRunning() );
	EXPECT_TRUE( SF_SUCCESS( sfThread1.Join() ) );
}
