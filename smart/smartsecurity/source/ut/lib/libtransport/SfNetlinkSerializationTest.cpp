/**
****************************************************************************************************
* @file SfNetlinkSerializationTest.cpp
* @test SfNetlinkSerializationTest.cpp
* @brief
* @author Vitalii Tykhenko (v.tykhnenko@samsung.com)
* @date Created Dec 22, 2014 17:18
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "libtransport/include/netlink/SfNetlinkSerialization.h"

#include <gtest/gtest.h>

//--------------------------------------------------------------------------------------------------

class SfNetlinkSerialization_TestSuite: public testing::Test
{
protected:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

/**
***************************************************************************************************
//@sut      vdapi_createNetlinkPacket_p SfNetlinkSerialization_TestSuite
//@brief    Netlink Create Packet Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfNetlinkSerialization_TestSuite, vdapi_createNetlinkPacket_p )
{
    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    SfDestroyNetlinkPacket( pPacket );
}

//--------------------------------------------------------------------------------------------------
