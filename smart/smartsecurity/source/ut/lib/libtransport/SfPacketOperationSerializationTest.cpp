/**
****************************************************************************************************
* @file SfPacketOperationSerializationTest.cpp
* @test SfPacketOperationSerializationTest.cpp
* @brief Serialization DeSearization packet operation test implementation.
* @author Vitalii Tykhenko (v.tykhnenko@samsung.com)
* @date Created December 17, 2014 09:22
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

extern "C"
{
    #include "libtransport/include/SfPacketOperationSerialization.h"
}
#include "libprotocol/SfOperationsFormat.h"
#include "TestUtils.h"

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <gtest/gtest.h>

//--------------------------------------------------------------------------------------------------

class SfPacketOperationSerialization_TestSuite: public testing::Test
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
//@sut      vdapi_serializePacketOperation_n SfPacketOperationSerialization_TestSuite
//@brief    Kernel packet Serialize Negative Test
//@input    packet
***************************************************************************************************
*/

TEST_F( SfPacketOperationSerialization_TestSuite, vdapi_serializePacketOperation_n )
{
    EXPECT_TRUE( SF_FAILED( SfSerializePacketOperation( NULL, NULL, 1 ) ) );

    SfOperationBlockRule op;
    EXPECT_TRUE( SF_FAILED( SfSerializePacketOperation( &op.header, NULL, 1 ) ) );

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_FAILED( SfSerializePacketOperation( NULL, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializePacketOperationBlockRule_p SfPacketOperationSerialization_TestSuite
//@brief    Kernel packet Serialize Positive Test
//@input    packet
***************************************************************************************************
*/

TEST_F( SfPacketOperationSerialization_TestSuite, vdapi_serializePacketOperationBlockRule_p )
{
    SfOperationBlockRule op = { { sizeof( SfOperationBlockRule ), SF_OPERATION_TYPE_RULE },
                                SF_RULE_FILE_OPEN, SF_RULE_ADD, 0, Uint64(-1) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketOperation( &op.header, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializePacketOperationSetupDUID_p SfPacketOperationSerialization_TestSuite
//@brief    Kernel packet Serialize Positive Test
//@input    packet
***************************************************************************************************
*/

TEST_F( SfPacketOperationSerialization_TestSuite, vdapi_serializePacketOperationSetupDUID_p )
{
    SfOperationSetupDUID op = { { sizeof( SfOperationSetupDUID ), SF_OPERATION_TYPE_SETUP_DUID },
                                "test_duid" };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketOperation( &op.header, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketOperation_n SfPacketOperationSerialization_TestSuite
//@brief    Kernel packet deserialize Negative Test
//@input    packet
***************************************************************************************************
*/

TEST_F( SfPacketOperationSerialization_TestSuite, vdapi_deserializePacketOperation_n )
{
    EXPECT_TRUE( SfDeserializePacketOperation( NULL ) == NULL );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketOperationBlockRule_p SfPacketOperationSerialization_TestSuite
//@brief    Kernel packet block rule deserialize positive Test
//@input    packet
***************************************************************************************************
*/

TEST_F( SfPacketOperationSerialization_TestSuite, vdapi_deserializePacketOperationBlockRule_p )
{
    SfOperationBlockRule inOp = { { sizeof( SfOperationBlockRule ), SF_OPERATION_TYPE_RULE },
                                  SF_RULE_FILE_OPEN, SF_RULE_ADD, 0, Uint64(-1) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );

    const int c_attrValue = 10;
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketOperation( &inOp.header, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfProtocolHeader* outOp = SfDeserializePacketOperation( pAttribute );
    EXPECT_TRUE( outOp != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &inOp.header, outOp ) );

    SfOperationBlockRule* pOperation = (SfOperationBlockRule*)outOp;
    EXPECT_TRUE( EqualOperationBlockRule( &inOp, pOperation ) );
    SfDestroyOperation( outOp );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketOperationSetupDUID_p SfPacketOperationSerialization_TestSuite
//@brief    Kernel packet duid deserialize positive Test
//@input    packet
***************************************************************************************************
*/
TEST_F( SfPacketOperationSerialization_TestSuite, vdapi_deserializePacketOperationSetupDUID_p )
{
    SfOperationSetupDUID inOp = { { sizeof( SfOperationSetupDUID ), SF_OPERATION_TYPE_SETUP_DUID },
                                  "12341234213421ABCDEF" };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );

    const int c_attrValue = 10;
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketOperation( &inOp.header, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfProtocolHeader* outOp = SfDeserializePacketOperation( pAttribute );
    EXPECT_TRUE( outOp != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &inOp.header, outOp ) );

    SfOperationSetupDUID* pOperation = (SfOperationSetupDUID*)outOp;
    EXPECT_TRUE( EqualOperationSetupDUID( &inOp, pOperation ) );
    SfDestroyOperation( outOp );
    SfDestroyNetlinkPacket( pPacket );
}

//--------------------------------------------------------------------------------------------------
