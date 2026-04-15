/**
****************************************************************************************************
* @file SfKernelConnectionTest.cpp
* @brief Security framework [SF] implementation: libsfkc is tested
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
#include "libsfkc/SfKernelConnection.h"
// third party
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <unistd.h>

//--------------------------------------------------------------------------------------------------

class SfKernelConnection_TestSuite: public testing::Test
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
//@sut      vdapi_connect SfKernelConnection_TestSuite
//@brief    Kernel socket connection Test
//@input    Packet
***************************************************************************************************
*/
TEST_F( SfKernelConnection_TestSuite, vdapi_connect )
{
    SfKernelConnection conn;
    EXPECT_FALSE( conn.IsConnected() );
    EXPECT_TRUE( SF_SUCCESS( conn.Connect() ) );
    EXPECT_TRUE( conn.IsConnected() );
}

/**
***************************************************************************************************
//@sut      vdapi_joinLeaveGroup SfKernelConnection_TestSuite
//@brief    Kernel socket JoinLeaveGroup Test
//@input    Packet
***************************************************************************************************
*/

TEST_F( SfKernelConnection_TestSuite, vdapi_joinLeaveGroup )
{
    SfKernelConnection conn;
    EXPECT_TRUE( SF_SUCCESS( conn.Connect() ) );

    const Uint c_groupCount = 4;
    SF_OPERATION_TYPE groups [ c_groupCount ] = { SF_OPERATION_TYPE_OPEN, SF_OPERATION_TYPE_CONNECT,
                                                  SF_OPERATION_TYPE_MMAP, SF_OPERATION_TYPE_EXEC };
    for ( Uint i = 0; i < c_groupCount; ++i )
    {
        EXPECT_TRUE( SF_SUCCESS( conn.JoinGroup( groups[ i ] ) ) );
        EXPECT_TRUE( SF_SUCCESS( conn.LeaveGroup( groups[ i ] ) ) );
    }
}

/**
***************************************************************************************************
//@sut      vdap_setupNetworkRule_p SfKernelConnection_TestSuite
//@brief    Firewall Network Rule Test
//@input    IP address
***************************************************************************************************
*/

TEST_F( SfKernelConnection_TestSuite, vdap_setupNetworkRule_p )
{
    SfKernelConnection conn;
    EXPECT_TRUE( SF_SUCCESS( conn.Connect() ) );

    const char* c_domainAddress = "54.229.9.4";
    struct sockaddr_in sa;
    inet_pton( AF_INET, c_domainAddress, &sa.sin_addr );

    EXPECT_TRUE( SF_SUCCESS( conn.SetupNetworkRule( sa.sin_addr.s_addr ) ) );
}

/**
***************************************************************************************************
//@sut      vdapi_setupOpenRule_p SfKernelConnection_TestSuite
//@brief    Firewall 'File' open Rule test
//@input    Inode
***************************************************************************************************
*/
TEST_F( SfKernelConnection_TestSuite, vdapi_setupOpenRule_p )
{
    SfKernelConnection conn;
    EXPECT_TRUE( SF_SUCCESS( conn.Connect() ) );

    Uint64 testInode = 1234567; // because why not
    EXPECT_TRUE( SF_SUCCESS( conn.SetupOpenRule( testInode ) ) );
}

//--------------------------------------------------------------------------------------------------
