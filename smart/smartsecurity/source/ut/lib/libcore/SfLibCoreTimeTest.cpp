/**
****************************************************************************************************
* @file SfLibCoreTimeTest.cpp
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
// third party
#include <gtest/gtest.h>

/**
****************************************************************************************************
* @class SfCoreTime_TestSuite
* @brief C++  Time operations tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfCoreTime_TestSuite: public testing::Test
{
protected:

	/**
	****************************************************************************************************
	* @brief Called before the first test in this test case
	****************************************************************************************************
	*/	static void SetUpTestCase()
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

protected://members

	static const Int32	NumTstVal 	 = 2;	//!< number of test time
	static const Int32  TimeTstDelay = 2000; //!< used to delay
	static const Uint64 MinTimeVal	 = 0;	//!< min range of time value
	static const Uint64 MaxTimeVal	 = 0xffffffffffffffff;//!< max range of time value
};

 /**
 ***************************************************************************************************
 //@sut      vdapi_SfGetSystemTimeUsecTest_p SfCoreTime_TestSuite
 //@brief    Get usec Positive Test
 //@input    Time Structure
 ***************************************************************************************************
 */
TEST_F(SfCoreTime_TestSuite, vdapi_SfGetSystemTimeUsecTest_p)
{
	Uint64 oldTime;
	for (Uint32 i = 0; i < NumTstVal; ++i)
	{
		oldTime = SfGetSystemTimeUsec();
		SfSleepMs(TimeTstDelay);
		EXPECT_TRUE(oldTime < SfGetSystemTimeUsec());
	}
}

 /**
 ***************************************************************************************************
 //@sut      vdapi_SfParseTimeStructureTest_p SfCoreTime_TestSuite
 //@brief    Time Structure Parsing Positive Test
 //@input    Time Structure
 ***************************************************************************************************
 */
TEST_F(SfCoreTime_TestSuite, vdapi_SfParseTimeStructureTest_p)
{
	Uint64 rsec = MaxTimeVal;
	SfTime time;

	/*
	* Min value parse time structure test
	*/
	SfParseTimeStructure(&time, MinTimeVal);
    EXPECT_EQ(static_cast<Uint32>(0), time.usec);
    EXPECT_EQ(static_cast<Uint32>(0), time.msec);
    EXPECT_EQ(static_cast<Uint32>(0), time.sec);
    EXPECT_EQ(static_cast<Uint32>(0), time.minutes);
    EXPECT_EQ(static_cast<Uint32>(0), time.hours);
    EXPECT_EQ(static_cast<Uint32>(0), time.days);

	/*
	* Max value parse time structure test
	*/
	SfParseTimeStructure( &time, rsec);
	EXPECT_EQ((rsec % 1000), time.usec);
	rsec /= 1000;
	EXPECT_EQ((rsec % 1000), time.msec);
	rsec /= 1000;
	EXPECT_EQ((rsec % 60), time.sec);
	rsec /= 60;
	EXPECT_EQ((rsec % 60), time.minutes);
	rsec /= 60;
	EXPECT_EQ((rsec % 24), time.hours);
	rsec /= 24;
    EXPECT_EQ(static_cast<Uint32>(rsec), time.days);
}
