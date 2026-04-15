/**
****************************************************************************************************
* @file SfProtokolHeaderSerializationTest.cpp
* @test SfProtokolHeaderSerializationTest.cpp
* @brief
* @author Vitalii Tykhenko (v.tykhnenko@samsung.com)
* @date Created Dec 15, 2014 10:39
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

extern "C"
{
    #include "libtransport/include/SfProtocolHeaderSerialization.h"
}
#include "TestUtils.h"

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <gtest/gtest.h>

//--------------------------------------------------------------------------------------------------

class ProtocolHeaderSerialization_TestSuite: public testing::Test
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
//@sut      vdapi_serializeProtocolHeader_n ProtocolHeaderSerialization_TestSuite
//@brief    Protocol Serialize Negative Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( ProtocolHeaderSerialization_TestSuite, vdapi_serializeProtocolHeader_n )
{
    EXPECT_TRUE( SF_FAILED( SfSerializeProtocolHeader( NULL, NULL, 1 ) ) );

    SfProtocolHeader header;
    EXPECT_TRUE( SF_FAILED( SfSerializeProtocolHeader( &header, NULL, 1 ) ) );

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_FAILED( SfSerializeProtocolHeader( NULL, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializeProtocolHeader_p ProtocolHeaderSerialization_TestSuite
//@brief    Protocol Serialize Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( ProtocolHeaderSerialization_TestSuite, vdapi_serializeProtocolHeader_p )
{
    SfProtocolHeader header;
    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializeProtocolHeader( &header, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeProtocolHeader_n ProtocolHeaderSerialization_TestSuite
//@brief    Protocol Deserialize Negative Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( ProtocolHeaderSerialization_TestSuite, vdapi_deserializeProtocolHeader_n )
{
    EXPECT_TRUE( SF_FAILED( SfDeserializeProtocolHeader( NULL, NULL ) ) );

    SfProtocolHeader header;
    EXPECT_TRUE( SF_FAILED( SfDeserializeProtocolHeader( &header, NULL ) ) );

    struct nlattr someAttr;
    EXPECT_TRUE( SF_FAILED( SfDeserializeProtocolHeader( NULL, &someAttr ) ) );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeProtocolHeader_p ProtocolHeaderSerialization_TestSuite
//@brief    Protocol Deserialize Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( ProtocolHeaderSerialization_TestSuite, vdapi_deserializeProtocolHeader_p )
{
    SfProtocolHeader inHdr = { 0, Uint32(-1) };
    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );

    const int c_attrValue = 10;
    EXPECT_TRUE( SF_SUCCESS( SfSerializeProtocolHeader( &inHdr, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfProtocolHeader outHdr;
    EXPECT_TRUE( SF_SUCCESS( SfDeserializeProtocolHeader( &outHdr, pAttribute ) ) );
    EXPECT_TRUE( EqualProtocolHeader( &inHdr, &outHdr ) );
    SfDestroyNetlinkPacket( pPacket );
}

//--------------------------------------------------------------------------------------------------
