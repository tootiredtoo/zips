/**
****************************************************************************************************
* @file SfSignalHandlerTest.cpp
* @brief Security framework [SF] implementation: libprimitive is tested
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
#include "libprimitive/SfSignalHandler.h"
// third party
#include <gtest/gtest.h>

/**
****************************************************************************************************
* @class SfSignalHandler_TestSuite
* @brief C++  The thread-primitive's posix-signal tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfSignalHandler_TestSuite: public testing::Test
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
//@sut      vdapi_SfSignalHandlerUseTest_p
//@brief    Test the system signal and events handler Positive Test
//@input    SfSignalHandler
***************************************************************************************************
*/
TEST_F(SfSignalHandler_TestSuite, vdapi_SfSignalHandlerUseTest_p)
{
	const Int32		sig_num = SIGUSR1;

	SfSignalHandler& sfSH = SfSignalHandler::GetInstance();

	EXPECT_TRUE( SF_SUCCESS( sfSH.CatchSignal(sig_num) ) );
	kill(getpid(), sig_num);
	EXPECT_TRUE( sfSH.IsSignalReceived( sig_num) );

	sfSH.PrintReceivedSignal();
}

/**
***************************************************************************************************
//@sut      vdapi_SfSignalHandlerUseTest_p
//@brief    Test the system signal and get sender PID Positive Test
//@input    SfSignalHandler
***************************************************************************************************
*/
TEST_F(SfSignalHandler_TestSuite, vdapi_SfSignalHandlerGetSenderPID_p)
{
	const Int32		sig_num = SIGUSR1;

	SfSignalHandler& sfSH = SfSignalHandler::GetInstance();

	EXPECT_TRUE( SF_SUCCESS( sfSH.CatchSignal(sig_num) ) );
	kill( getpid(), sig_num );
	int callerPID = sfSH.GetSenderPID();
	EXPECT_EQ ( getpid(), callerPID );
}

/**
***************************************************************************************************
//@sut      vdapi_SfSignalHandlerUseTest_p
//@brief    Test the system signal and get sender process name Positive Test
//@input    SfSignalHandler
***************************************************************************************************
*/
TEST_F(SfSignalHandler_TestSuite, vdapi_SfSignalHandlerGetSenderProcessName_p)
{
	const Int32		sig_num = SIGUSR1;

	SfSignalHandler& sfSH = SfSignalHandler::GetInstance();

	EXPECT_TRUE( SF_SUCCESS( sfSH.CatchSignal(sig_num) ) );
	kill( getpid(), sig_num );
	std::string callerName = sfSH.GetSenderProcessName();
	EXPECT_STREQ ( "SfTestApp", callerName.c_str() );
}
