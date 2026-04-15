/**
****************************************************************************************************
* @file SfNodeJSONTest.h
* @brief Security framework [SF] unit test for class json/SfNode.h
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jul 2, 2014 09:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_NODE_JSON_TEST_H_
#define _SF_NODE_JSON_TEST_H_

// project
#include "data_translation/json/SfJSONNode.h"
#include "data_translation/json/SfJSONArrayNode.h"

// third party
#include <cppunit/extensions/HelperMacros.h>

/**
****************************************************************************************************
*
****************************************************************************************************
*/
class SfNodeJSONTest : public CppUnit::TestFixture
{
private:
     CPPUNIT_TEST_SUITE( SfNodeJSONTest );
     CPPUNIT_TEST( TestParseToString );
     CPPUNIT_TEST( TestManualBuildNodeToString );
     CPPUNIT_TEST( TestPutGetNode );
     CPPUNIT_TEST( TestNodePutGetValue );
     CPPUNIT_TEST( TestArrayNodePutGetValue );
     CPPUNIT_TEST_SUITE_END();

public: // methods
    SfNodeJSONTest();
    ~SfNodeJSONTest();

    void TestParseToString();
    void TestManualBuildNodeToString();
    void TestPutGetNode();
    void TestNodePutGetValue();
    void TestArrayNodePutGetValue();

private: // methods
    void BuildDefaultNode( SfJSONNode& node );
    void BuildDefaultSimpleArrayNode( SfJSONArrayNode& node );

}; // class SfNodeJSONTest

#endif /* _SF_NODE_JSON_TEST_H_ */
