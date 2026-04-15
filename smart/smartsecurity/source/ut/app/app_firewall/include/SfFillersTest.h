/**
****************************************************************************************************
* @file SfFillersTest.h
* @brief Security framework [SF] unit test for class data_translation/fillers/SfFillers.h
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jul 14, 2014 09:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_FILLERS_TEST_H_
#define _SF_FILLERS_TEST_H_

// project
#include "libprotocol/SfEnvironmentFormat.h"

// third party
#include <cppunit/extensions/HelperMacros.h>

/**
****************************************************************************************************
*
****************************************************************************************************
*/
class SfJSONNode;

class SfFillersTest : public CppUnit::TestFixture
{
private:
    CPPUNIT_TEST_SUITE( SfFillersTest );
    CPPUNIT_TEST( TestFillFilters );
    CPPUNIT_TEST( TestFillJSONString );
    CPPUNIT_TEST( TestFillSfConfig );
    CPPUNIT_TEST_SUITE_END();

public: // methods
     SfFillersTest();
     ~SfFillersTest();

     void TestFillFilters();
     void TestFillJSONString();
     void TestFillSfConfig();

private: // methods
     void TestFillFileEnvFilter1();
     void TestFillFileEnvFilter2();
     void TestFillFileEnvFilter( SfJSONNode& openEventNode );
     void TestFillProcEnvFilter1();
     void TestFillProcEnvFilter2();
     void TestFillProcEnvFilter( SfJSONNode& procEventNode );
     void TestFillNetEnvFilter1();
     void TestFillNetEnvFilter2();
     void TestFillNetEnvFilter( SfJSONNode& netEventNode );

     void TestFillJSONStringBySfFileEnv();
     void TestFillJSONStringBySfProcEnv();
     void TestFillJSONStringBySfNetEnv();

     void FillDefault( SfFileEnvironment& fileEnv );
     void FillDefault( SfProcessEnvironment& procEnv );
     void FillDefault( SfNetworkEnvironment& netEnv );

}; // class SfFillersTest

#endif /* _SF_FILLERS_TEST_H_ */
