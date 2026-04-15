/**
****************************************************************************************************
* @file SfConditionVariableTest.cpp
* @brief Security framework [SF] implementation: libprimitive is tested
* @author Viacheslav Vovchenko (v.vovchenko@samsung.com)
* @date November 28, 2014 18:00.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

// project
#include "libprimitive/SfMutex.h"
#include "libprimitive/SfConditionVariable.h"
// third party
#include <gtest/gtest.h>

/**
****************************************************************************************************
* @class SfConditionVariable_TestSuite
* @brief C++  The thread-primitive's condition variable tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfConditionVariable_TestSuite: public testing::Test
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
//@sut      vdapi_SfConditionVariableUseTest_p SfConditionVariable_TestSuite
//@brief    Test condition variable and Mutex implementation Positive Test
//@input    Mutex
***************************************************************************************************
*/
TEST_F(SfConditionVariable_TestSuite, vdapi_SfConditionVariableUseTest_p)
{
	SfMutex sfMutex;
	SfConditionVariable sfCV;

	sfCV.NotifyOne();
	sfCV.Wait( sfMutex );

	sfCV.NotifyAll();
	sfCV.Wait( sfMutex );
}
