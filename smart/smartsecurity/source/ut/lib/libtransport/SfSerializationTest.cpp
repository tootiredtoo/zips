/**
****************************************************************************************************
* @file SfSerializationTest.cpp
* @test SfSerializationTest.cpp
* @brief
* @author Vitalii Tykhenko (v.tykhnenko@samsung.com)
* @date Created Dec 22, 2014 9:05
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "libtransport/include/SfSerialization.h"
#include "TestUtils.h"

#include <gtest/gtest.h>

//--------------------------------------------------------------------------------------------------

class SfSerialization_TestSuite: public testing::Test
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
//@sut      vdapi_serializePacket_n SfSerialization_TestSuite
//@brief    Netlink Serialize Negative Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_serializePacket_n )
{
    EXPECT_TRUE( SfSerializePacket( NULL ) == NULL );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacket_n SfSerialization_TestSuite
//@brief    Netlink Derialize Negative Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_deserializePacket_n )
{
    EXPECT_TRUE( SfDeserializePacket( NULL ) == NULL );
}

/**
***************************************************************************************************
//@sut      vdapi_serializePacketHeader_p SfSerialization_TestSuite
//@brief    Netlink Serialize Header Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_serializePacketHeader_p )
{
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, NULL, NULL, 0 };

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );
    SfDestroyNetlinkPacket( pNPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketHeader_p SfSerialization_TestSuite
//@brief    Netlink Deserialize Header Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_deserializePacketHeader_p )
{
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, NULL, NULL, 0 };

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );

    SfPacket* pOutPacket = SfDeserializePacket( pNPacket );
    EXPECT_TRUE( pOutPacket != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &packet.header, &pOutPacket->header ) );
    EXPECT_TRUE( pOutPacket->env == NULL );
    EXPECT_TRUE( pOutPacket->op == NULL );
    SfDestroyPacket( pOutPacket );
    SfDestroyNetlinkPacket( pNPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializePacketEnv_p SfSerialization_TestSuite
//@brief    Netlink Serialize Environment Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_serializePacketEnv_p )
{
    SfFileEnvironment env = { { sizeof( SfFileEnvironment ), SF_ENVIRONMENT_TYPE_FILE },
                              { "test_process", Uint32( -1 ), 0, 100 },
                              "test_file", Uint64( -1 ) };
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, &env.header, NULL , 0};

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );
    SfDestroyNetlinkPacket( pNPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketEnv_p SfSerialization_TestSuite
//@brief    Netlink Deserialize opetaion Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_deserializePacketEnv_p )
{
    SfFileEnvironment env = { { sizeof( SfFileEnvironment ), SF_ENVIRONMENT_TYPE_FILE },
                              { "test_process", Uint32( -1 ), 0, 100 },
                              "test_file", Uint64( -1 ) };
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, &env.header, NULL, 0 };

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );

    SfPacket* pOutPacket = SfDeserializePacket( pNPacket );
    EXPECT_TRUE( pOutPacket != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &packet.header, &pOutPacket->header ) );
    EXPECT_TRUE( pOutPacket->op == NULL );
    EXPECT_TRUE( pOutPacket->env != NULL );
    EXPECT_TRUE( EqualProtocolHeader( packet.env, pOutPacket->env ) );
    EXPECT_TRUE( EqualFileEnvironment( (SfFileEnvironment*)(packet.env),
                                       (SfFileEnvironment*)(pOutPacket->env) ) );

    SfDestroyPacket( pOutPacket );
    SfDestroyNetlinkPacket( pNPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializePacketOp_p SfSerialization_TestSuite
//@brief    Netlink Serialize opetaion Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_serializePacketOp_p )
{
    SfOperationBlockRule op = { { sizeof( SfOperationBlockRule ), SF_OPERATION_TYPE_RULE },
                                SF_RULE_FILE_OPEN, SF_RULE_ADD, 0, Uint64(-1) };
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, NULL, &op.header, 0 };

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );
    SfDestroyNetlinkPacket( pNPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketOp_p SfSerialization_TestSuite
//@brief    Netlink Deserialize opetaion Positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_deserializePacketOp_p )
{
    SfOperationBlockRule op = { { sizeof( SfOperationBlockRule ), SF_OPERATION_TYPE_RULE },
                                SF_RULE_FILE_OPEN, SF_RULE_ADD, 0, Uint64(-1) };
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, NULL, &op.header, 0 };

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );

    SfPacket* pOutPacket = SfDeserializePacket( pNPacket );
    EXPECT_TRUE( pOutPacket != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &packet.header, &pOutPacket->header ) );
    EXPECT_TRUE( pOutPacket->env == NULL );
    EXPECT_TRUE( pOutPacket->op != NULL );
    EXPECT_TRUE( EqualProtocolHeader( packet.op, pOutPacket->op ) );
    EXPECT_TRUE( EqualOperationBlockRule( (SfOperationBlockRule*)(packet.op),
                                          (SfOperationBlockRule*)(pOutPacket->op) ) );

    SfDestroyPacket( pOutPacket );
    SfDestroyNetlinkPacket( pNPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializePacketComplete_p SfSerialization_TestSuite
//@brief    Netlink Serialize positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_serializePacketComplete_p )
{
    SfProcessEnvironment env = { { sizeof( SfProcessEnvironment ), SF_ENVIRONMENT_TYPE_PROCESS },
                                 { "test_process", Uint32( -1 ), 0, 100 },
                                 "test_file", Uint64( -1 ) };
    SfOperationSetupDUID op = { { sizeof( SfOperationSetupDUID ), SF_OPERATION_TYPE_SETUP_DUID },
                                "test_duid" };
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, &env.header, &op.header, 0 };

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );
    SfDestroyNetlinkPacket( pNPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketComplete_p SfSerialization_TestSuite
//@brief    Netlink Deserialize positive Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfSerialization_TestSuite, vdapi_deserializePacketComplete_p )
{
    SfProcessEnvironment env = { { sizeof( SfProcessEnvironment ), SF_ENVIRONMENT_TYPE_PROCESS },
                                 { "test_process", Uint32( -1 ), 0, 100 },
                                 "test_file", Uint64( -1 ) };
    SfOperationSetupDUID op = { { sizeof( SfOperationSetupDUID ), SF_OPERATION_TYPE_SETUP_DUID },
                                "test_duid" };
    SfPacket packet = { { sizeof(SfPacket), SF_PACKET_TYPE_OPERATION }, &env.header, &op.header, 0 };

    SfNetlinkPacket* pNPacket = SfSerializePacket( &packet );
    EXPECT_TRUE( pNPacket != NULL );

    SfPacket* pOutPacket = SfDeserializePacket( pNPacket );
    EXPECT_TRUE( pOutPacket != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &packet.header, &pOutPacket->header ) );
    EXPECT_TRUE( pOutPacket->env != NULL );
    EXPECT_TRUE( EqualProtocolHeader( packet.env, pOutPacket->env ) );
    EXPECT_TRUE( EqualProcessEnvironment( (SfProcessEnvironment*)packet.env,
                                          (SfProcessEnvironment*)pOutPacket->env ) );
    EXPECT_TRUE( pOutPacket->op != NULL );
    EXPECT_TRUE( EqualProtocolHeader( packet.op, pOutPacket->op ) );
    EXPECT_TRUE( EqualOperationSetupDUID( (SfOperationSetupDUID*)packet.op,
                                          (SfOperationSetupDUID*)pOutPacket->op ) );

    SfDestroyPacket( pOutPacket );
    SfDestroyNetlinkPacket( pNPacket );
}

//--------------------------------------------------------------------------------------------------
