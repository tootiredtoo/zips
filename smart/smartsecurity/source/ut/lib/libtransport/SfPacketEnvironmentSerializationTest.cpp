/**
****************************************************************************************************
* @file SfPacketEnvironmentSerializationTest.cpp
* @test SfPacketEnvironmentSerializationTest.cpp
* @brief Serialization DeSearization packet environment test implementation.
* @author Vitalii Tykhenko (v.tykhnenko@samsung.com)
* @date Created November 28, 2014 14:25
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

extern "C"
{
    #include "libtransport/include/SfPacketEnvironmentSerialization.h"
}
#include "TestUtils.h"

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <gtest/gtest.h>

//--------------------------------------------------------------------------------------------------

class SfPacketEnvironmentSerialization_TestSuite: public testing::Test
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
//@sut      vdapi_serializeExecEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Execution Envrionment Serialize Negative Test
//@input    SfExecutionEnvironmentInfo
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_serializeExecEnv_n )
{
    EXPECT_TRUE( SF_FAILED( SfSerializeExecutionEnvironment( NULL, NULL, 1 ) ) );

    SfExecutionEnvironmentInfo env;
    EXPECT_TRUE( SF_FAILED( SfSerializeExecutionEnvironment( &env, NULL, 1 ) ) );

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_FAILED( SfSerializeExecutionEnvironment( NULL, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializeExecEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Execution Envrionment Serialize Positive Test
//@input    SfExecutionEnvironmentInfo
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_serializeExecEnv_p )
{
    SfExecutionEnvironmentInfo env = { "test_process", Uint32( -1 ), 0, 1 };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializeExecutionEnvironment( &env, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeExecEnv_n SfPacketEnvironmentSerialization_TestSuite
//@brief    Execution Envrionment Deserialize Negative Test
//@input    SfExecutionEnvironmentInfo
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_deserializeExecEnv_n )
{
    SfExecutionEnvironmentInfo env;
    EXPECT_TRUE( SF_FAILED( SfDeserializeExecutionEnvironment( &env, NULL ) ) );

    struct nlattr testAttr;
    EXPECT_TRUE( SF_FAILED( SfDeserializeExecutionEnvironment( NULL, &testAttr ) ) );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeExecEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Packet Envrionment Serialize Positive Test
//@input    SfProtocolHeader,SfNetlinkPacket
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_deserializeExecEnv_p )
{
    SfExecutionEnvironmentInfo inEnv = { "test_process", Uint32( -1 ), 0, 1 };

    const int c_attrValue = 10;
    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializeExecutionEnvironment( &inEnv, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfExecutionEnvironmentInfo outEnv = {0,0,0,0};
    
    EXPECT_TRUE( SF_SUCCESS( SfDeserializeExecutionEnvironment( &outEnv, pAttribute ) ) );
    EXPECT_TRUE( EqualExecEnvironment( &inEnv, &outEnv ) );
    sf_free(outEnv.pProcessName);
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializePacketEnv_n SfPacketEnvironmentSerialization_TestSuite
//@brief    Packet Envrionment Serialize Negative Test
//@input    SfProtocolHeader,SfNetlinkPacket
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_serializePacketEnv_n )
{
    EXPECT_TRUE( SF_FAILED( SfSerializePacketEnvironment( NULL, NULL, 1 ) ) );

    SfProtocolHeader hdr;
    EXPECT_TRUE( SF_FAILED( SfSerializePacketEnvironment( &hdr, NULL, 1 ) ) );

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_FAILED( SfSerializePacketEnvironment( NULL, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializeFileEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    File Envrionment Serialize Positive Test
//@input    SfFileEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_serializeFileEnv_p )
{
    SfFileEnvironment env = { { sizeof( SfFileEnvironment ), SF_ENVIRONMENT_TYPE_FILE },
                              { "test_process", Uint32( -1 ), 0, 100 },
                              "test_file", Uint64( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializeProcEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Process Envrionment Serialize Positive Test
//@input    SfProcessEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_serializeProcEnv_p )
{
    SfProcessEnvironment env = { { sizeof( SfProcessEnvironment ), SF_ENVIRONMENT_TYPE_PROCESS },
                                 { "test_process", Uint32( -1 ), 0, 100 },
                                 "test_file", Uint64( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializeNetworkEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Network Envrionment Serialize Positive Test
//@input    SfNetworkEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_serializeNetworkEnv_p )
{
    SfNetworkEnvironment env = { { sizeof( SfNetworkEnvironment ), SF_ENVIRONMENT_TYPE_NETWORK },
                                 { "test_process", Uint32( -1 ), 0, 100 },
                                 0, Uint16( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_serializeMmapEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Mmap Envrionment Serialize Positive Test
//@input    SfMmapEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_serializeMmapEnv_p )
{
    SfMmapEnvironment env = { { sizeof( SfMmapEnvironment ), SF_ENVIRONMENT_TYPE_MMAP },
                              { "test_process", Uint32( -1 ), 0, 100 },
                              "test_library_name", Uint64( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, 1 ) ) );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializePacketEnv_n SfPacketEnvironmentSerialization_TestSuite
//@brief    Packet Envrionment Deserialize Negative Test
//@input    NULL
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_deserializePacketEnv_n )
{
    EXPECT_TRUE( SfDeserializePacketEnvironment( NULL ) == NULL );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeFileEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    File Envrionment Deserialize Positive Test
//@input    SfFileEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_deserializeFileEnv_p )
{
    SfFileEnvironment env = { { sizeof( SfFileEnvironment ), SF_ENVIRONMENT_TYPE_FILE },
                              { "test_process", Uint32( -1 ), 0, 100 },
                              "test_file", Uint64( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );

    const int c_attrValue = 10;
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfProtocolHeader* pOutHdr = SfDeserializePacketEnvironment( pAttribute );
    EXPECT_TRUE( pOutHdr != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &env.header, pOutHdr ) );

    SfFileEnvironment* pOutEnv = (SfFileEnvironment*)pOutHdr;
    EXPECT_TRUE( EqualFileEnvironment( &env, pOutEnv ) );
    SfDestroyEnvironment( pOutHdr );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeProcEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Process Envrionment Deserialize Positive Test
//@input    SfProcessEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_deserializeProcEnv_p )
{
    SfProcessEnvironment env = { { sizeof( SfProcessEnvironment ), SF_ENVIRONMENT_TYPE_PROCESS },
                                 { "test_process", Uint32( -1 ), 0, 100 },
                                 "test_file", Uint64( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );

    const int c_attrValue = 10;
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfProtocolHeader* pOutHdr = SfDeserializePacketEnvironment( pAttribute );
    EXPECT_TRUE( pOutHdr != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &env.header, pOutHdr ) );

    SfProcessEnvironment* pOutEnv = (SfProcessEnvironment*)pOutHdr;
    EXPECT_TRUE( EqualProcessEnvironment( &env, pOutEnv ) );
    SfDestroyEnvironment( pOutHdr );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeNetworkEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Network Envrionment Deserialize Positive Test
//@input    SfNetworkEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_deserializeNetworkEnv_p )
{
    SfNetworkEnvironment env = { { sizeof( SfNetworkEnvironment ), SF_ENVIRONMENT_TYPE_NETWORK },
                                 { "test_process", Uint32( -1 ), 0, 100 },
                                 0, Uint16( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );

    const int c_attrValue = 10;
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfProtocolHeader* pOutHdr = SfDeserializePacketEnvironment( pAttribute );
    EXPECT_TRUE( pOutHdr != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &env.header, pOutHdr ) );

    SfNetworkEnvironment* pOutEnv = (SfNetworkEnvironment*)pOutHdr;
    EXPECT_TRUE( EqualNetworkEnvironment( &env, pOutEnv ) );
    SfDestroyEnvironment( pOutHdr );
    SfDestroyNetlinkPacket( pPacket );
}

/**
***************************************************************************************************
//@sut      vdapi_deserializeMmapEnv_p SfPacketEnvironmentSerialization_TestSuite
//@brief    Mmap Envrionment Deserialize Positive Test
//@input    SfMmapEnvironment
***************************************************************************************************
*/

TEST_F( SfPacketEnvironmentSerialization_TestSuite, vdapi_deserializeMmapEnv_p )
{
    SfMmapEnvironment env = { { sizeof( SfMmapEnvironment ), SF_ENVIRONMENT_TYPE_MMAP },
                              { "test_process", Uint32( -1 ), 0, 100 },
                              "test_library_name", Uint64( -1 ) };

    SfNetlinkPacket* pPacket = SfCreateNetlinkPacket();
    EXPECT_TRUE( pPacket != NULL );

    const int c_attrValue = 10;
    EXPECT_TRUE( SF_SUCCESS( SfSerializePacketEnvironment( &env.header, pPacket, c_attrValue ) ) );

    struct nlattr* pAttribute = nlmsg_attrdata( nlmsg_hdr( pPacket->pBuffer ), 0 );
    EXPECT_EQ( nla_type( pAttribute ), c_attrValue );

    SfProtocolHeader* pOutHdr = SfDeserializePacketEnvironment( pAttribute );
    EXPECT_TRUE( pOutHdr != NULL );
    EXPECT_TRUE( EqualProtocolHeader( &env.header, pOutHdr ) );

    SfMmapEnvironment* pOutEnv = (SfMmapEnvironment*)pOutHdr;
    EXPECT_TRUE( EqualMmapEnvironment( &env, pOutEnv ) );
    SfDestroyEnvironment( pOutHdr );
    SfDestroyNetlinkPacket( pPacket );
}

//--------------------------------------------------------------------------------------------------
