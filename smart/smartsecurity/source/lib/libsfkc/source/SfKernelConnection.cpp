/**
****************************************************************************************************
* @file SfKernelConnection.cpp
* @brief Security framework [SF] implementation: receive message from kernel
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created May 28, 2014 09:39
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
// local
#include "SfKernelConnection.h"
#include "SfNetlinkSocket.h"
#include "source/lib/libtransport/include/SfSerialization.h"
#include "netlink/netlink.h"

#include <arpa/inet.h>

#define SF_NOT_MEANNING 1
/**
****************************************************************************************************
*
****************************************************************************************************
*/
static int NetlinkCallback( struct nl_msg* pMessage, void* arg )
{
    SfNetlinkPacket nlkPacket;
    nlkPacket.pBuffer = pMessage;
    SfPacket* pPacket = SfDeserializePacket( &nlkPacket );
    static_cast< SfKernelConnection* >( arg )->SetPacket( pPacket );

    if ( !pPacket )
        SF_LOG_E( "[Deserializing failed];" );

    return NL_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfKernelConnection::SfKernelConnection()
    : m_pSocket( SF_NEW SfNetlinkSocket )
    , m_pPacket( NULL )
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfKernelConnection::~SfKernelConnection()
{
    SF_DELETE m_pSocket;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::Connect()
{
    SF_STATUS status = EstablishKernelConnection();
    do
    {
        if ( SF_FAILED( status ) )
        {
            SF_LOG_E( "[kernel connection failed];" );
            break;
        }

        status = SetupSocketBuffSize();
        if ( SF_FAILED( status ) )
        {
            SF_LOG_E( "[setting socket buffer failed];" );
            break;
        }
    } while( FALSE );

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::ReadyForRead( __suseconds_t timeOutMicroSec) const
{
    return m_pSocket->ReadyForRead( timeOutMicroSec );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::JoinGroup( SF_OPERATION_TYPE group )
{
    if ( SF_FAILED( m_pSocket->JoinGroup( group ) ) )
    {
        SF_LOG_E( "[JoinGroup(%d) failed];", group );
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::LeaveGroup( SF_OPERATION_TYPE group )
{
    if ( SF_FAILED( m_pSocket->LeaveGroup( group ) ) )
    {
        SF_LOG_E( "[LeaveGroup(%d) failed];", group );
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::Receive( SfPacket*& pPacket )
{
    if ( SF_FAILED( m_pSocket->Receive() ) )
    {
        SF_LOG_I( "Receive failed;" );
        return SF_STATUS_FAIL;
    }
    pPacket = m_pPacket;

    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::Send( const SfPacket* pPacket )
{
    return m_pSocket->Send( pPacket );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::EstablishKernelConnection()
{
    return m_pSocket->Connect( 10, c_second /*/ 10*/, NetlinkCallback, this );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::SetupSocketBuffSize()
{
    const Uint32 c_rcvBufferSize = 7 * 1024 * 1024;
    if ( SF_FAILED( m_pSocket->SetReceiveBufferSize( c_rcvBufferSize ) ) )
    {
        SF_LOG_E( "[setting socket buffer failed];" );
        return SF_STATUS_FAIL;
    }

    Uint32 actualBufferSize = 0;
    if ( SF_FAILED( m_pSocket->GetReceiveBufferSize( actualBufferSize ) ) )
    {
        SF_LOG_E( "[getting buffer size failed];" );
        return SF_STATUS_FAIL;
    }

    if ( actualBufferSize < c_rcvBufferSize )
        SF_LOG_W( "Try set = [%u], actual buffer = [%u];", c_rcvBufferSize, actualBufferSize );

    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::SetupNetworkRule( Uint32 addr )
{
    SfPacket packet;
    memset( &packet, 0, sizeof(SfPacket) );
    packet.header.type = SF_PACKET_TYPE_NOTIFICATION;
    packet.header.size = sizeof(SfPacket);

    SfOperationBlockRule rule;
    memset( &rule, 0, sizeof(SfOperationBlockRule) );
    rule.header.type = SF_OPERATION_TYPE_RULE;
    rule.header.size = sizeof(SfOperationBlockRule);
    rule.ruleType = SF_RULE_SOCKET_CONNECT;
    rule.action = SF_RULE_ADD;
    rule.ipAddr = addr;

    packet.op = (SfProtocolHeader*)&rule;

    return m_pSocket->Send( &packet );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::SetupOpenRule( Uint64 inode )
{
    SfPacket packet;
    memset( &packet, 0, sizeof(SfPacket) );
    packet.header.type = SF_PACKET_TYPE_NOTIFICATION;
    packet.header.size = sizeof(SfPacket);

    SfOperationBlockRule rule;
    memset( &rule, 0, sizeof(SfOperationBlockRule) );
    rule.header.type = SF_OPERATION_TYPE_RULE;
    rule.header.size = sizeof(SfOperationBlockRule);
    rule.ruleType = SF_RULE_FILE_OPEN;
    rule.action = SF_RULE_ADD;
    rule.fileInode = inode;

    packet.op = (SfProtocolHeader*)&rule;

    return m_pSocket->Send( &packet );
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::DeleteAllRules()
{
    SfPacket packet;
    memset( &packet, 0, sizeof(SfPacket) );
    packet.header.type = SF_PACKET_TYPE_NOTIFICATION;
    packet.header.size = sizeof(SfPacket);

    SfOperationBlockRule rule;
    memset( &rule, 0, sizeof(SfOperationBlockRule) );
    rule.header.type = SF_OPERATION_TYPE_RULE;
    rule.header.size = sizeof(SfOperationBlockRule);
    rule.ruleType = SF_RULE_FILE_OPEN;
    rule.action = SF_RULE_DEL;
    rule.fileInode = SF_NOT_MEANNING;

    packet.op = (SfProtocolHeader*)&rule;

    return m_pSocket->Send( &packet );
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfKernelConnection::SetupSndRcvRule( SfPacket& packet )
{
    return m_pSocket->Send( &packet );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfKernelConnection::SetPacket( SfPacket* pPacket )
{
    if ( !pPacket )
        SF_LOG_E( "[invalid param];" );

    m_pPacket = pPacket;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfKernelConnection::IsConnected() const
{
    return m_pSocket->IsConnected();
}

