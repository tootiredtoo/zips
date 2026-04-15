/**
****************************************************************************************************
* @file SfUnixSocketTest.cpp
* @brief Security framework [SF] implementation: libprimitive is tested
* @author Viacheslav Vovchenko (v.vovchenko@samsung.com)
* @date November 27, 2014 18:00.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

// third party
#include <gtest/gtest.h>
// project
#include "libprimitive/UnixSocket.h"
#include "libprimitive/SfThread.h"

/**
****************************************************************************************************
* @class SfUnixSocket_TestSuite
* @brief C++  The socket-primitive's tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfUnixSocket_TestSuite: public testing::Test
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

	/**
	****************************************************************************************************
	* @brief Function is executes a thread
	* @param [in] Not used
	* @return NULL Not used
	****************************************************************************************************
	*/
	static void* ThreadFunc( void* pContext );

protected:
	// members
	static const char m_strAddr[];//!< Address of server in this case to use only localhost
	static const char m_strData[];//!< Text of message to send/receive
};

//static variables
const char SfUnixSocket_TestSuite::m_strAddr[] = "127.0.0.1";
const char SfUnixSocket_TestSuite::m_strData[] = "GOOD";

// digit for waiting for server's initializing connection.
int g_Digit_for_Connect = 0;

/**
****************************************************************************************************
* @brief Function is executes a thread
* @param [in] 	Not used
* @return NULL 	Not used
****************************************************************************************************
*/
void* SfUnixSocket_TestSuite::ThreadFunc( void* pContext )
{
	UnixSocket sockConn;

    while (TRUE)
    {
        SfSleepMs(1000);
        if (g_Digit_for_Connect)
        {
            break;
        }
    }

	//Connect to server
	if( SF_SUCCESS( sockConn.ConnectToHost( m_strAddr) ) )
	{
		//Send string of test data to server
		sockConn.SendString(m_strData);
		
	}
	//Socket shold be disconnect
	sockConn.Disconnect();

	return NULL;
}

/**
***************************************************************************************************
//@sut      vdapi_SfUnixSocketUseTest_p SfUnixSocket_TestSuite
//@brief    Test connection/send/receive operations Positive Test
//@input    UnixSocket
***************************************************************************************************
*/
TEST_F(SfUnixSocket_TestSuite, vdapi_SfUnixSocketUseTest_p)
{
	//Socket and thread variables wraps
	UnixSocket sockConn, sockClient;
	SfThread sfThread1( "Client" );
	
	g_Digit_for_Connect = 0;

	//Create thread
	EXPECT_TRUE( SF_SUCCESS( sfThread1.Start( ThreadFunc, NULL) ) );
	//Checking running state
	EXPECT_TRUE( TRUE == sfThread1.IsRunning() );
	//Configuration socket and to set max connections
	EXPECT_TRUE( SF_SUCCESS(sockConn.SetupHost(m_strAddr, 1 ) ));
	
	// allow to connect
	g_Digit_for_Connect = 1;
	
	//Accept connection of client use to timeout 3000
	EXPECT_TRUE( SF_SUCCESS(sockConn.AcceptConnection(sockClient, 3000, TRUE)) );

	//Testing string data will receive of thread
	std::string strData;
	EXPECT_TRUE( TRUE == sockClient.IsConnected() );
	EXPECT_TRUE( TRUE == sockClient.ReceiveString(strData) );
	EXPECT_STREQ( m_strData, strData.c_str());
	//
	EXPECT_TRUE( SF_SUCCESS( sfThread1.Join() ));

	EXPECT_TRUE( SF_SUCCESS(sockClient.Disconnect() ));
	EXPECT_TRUE( SF_SUCCESS(sockConn.Disconnect() ));
}
