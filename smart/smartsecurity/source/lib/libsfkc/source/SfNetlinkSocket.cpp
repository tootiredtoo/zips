/**
****************************************************************************************************
* @file SfNetlinkSocket.cpp
* @brief Security framework [SF] implementation: wrap netlink socket functions
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created May 16, 2014 17:00.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
// local
#include "SfNetlinkSocket.h"

// project
#include "netlink/netlink.h"
#include "netlink/errno.h"

// system
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>

/**
****************************************************************************************************
* @brief Defines
****************************************************************************************************
*/
#ifndef SOL_NETLINK
    #define SOL_NETLINK 270
#endif

/**
****************************************************************************************************
* @class SfNetlinkSocket
****************************************************************************************************
*/
SfNetlinkSocket::SfNetlinkSocket()
    : m_pRWlock( new SfRWLock() )
    , m_pNode( NULL )
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfNetlinkSocket::~SfNetlinkSocket()
{
    m_pRWlock->WriteLock();
    if( NULL != m_pNode )
    {
        if ( SF_FAILED( SfDestroyNode( m_pNode ) ) )
             SF_LOG_E( "[freeing netlink node failed];" );

        m_pNode = NULL;
    }
    m_pRWlock->Unlock();

    delete m_pRWlock;
    m_pRWlock = NULL;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::Connect( Uint8 retriesCount, Ulong timeOutMs,
                                    nl_recvmsg_msg_cb_t callback, void* arg )
{
    for ( Uint8 i = 0; i < retriesCount; i++ )
    {
        if ( SF_SUCCESS( CreateSocket() ) &&
             SF_SUCCESS( GetSocketName() ) &&
             SF_SUCCESS( SetNonBlocking() ) )
        {
            m_pRWlock->ReadLock();
            if( NULL != m_pNode )
            {
                if( !nl_socket_modify_cb( m_pNode->pHandle, NL_CB_VALID, NL_CB_CUSTOM, callback, arg ) )
                {
                    nl_socket_disable_seq_check( m_pNode->pHandle );
                    m_pRWlock->Unlock();
                    return SF_STATUS_OK;
                }
            }
            m_pRWlock->Unlock();
        }
        SF_LOG_W( "Connect() failed : count %u;", i );

        m_pRWlock->WriteLock();
        sf_free(m_pNode); 
        m_pRWlock->Unlock();

        SfSleepMs(timeOutMs);
    }

    return SF_STATUS_FAIL;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::ReadyForRead( __suseconds_t timeOutMicroSec ) const
{
    m_pRWlock->ReadLock();
    if( NULL == m_pNode )
    {
        m_pRWlock->Unlock();
        return SF_STATUS_FAIL;
    }

    Int socketFd = nl_socket_get_fd( m_pNode->pHandle );
    m_pRWlock->Unlock();
    if ( -1 == socketFd )
    {
        SF_LOG_E( "[invalid descriptor];" );
        return SF_STATUS_FAIL;
    }

    struct timeval tv;
    tv.tv_sec = timeOutMicroSec / 1000000UL;
    tv.tv_usec = timeOutMicroSec % 1000000UL;

    fd_set rfds;
    FD_ZERO( &rfds );
    FD_SET( socketFd, &rfds );

    SF_STATUS result = SF_STATUS_FAIL;
    const Int retval = select( socketFd + 1, &rfds, NULL, NULL, &tv );
    if ( retval < 0 )
    {
        SF_LOG_E( "[select failed(%s)];", SF_GET_SYSTEM_ERROR( errno ) );
    }
    else if ( ( retval > 0 ) && FD_ISSET( socketFd, &rfds ) )
    {
        result = SF_STATUS_OK;
    }
    return result;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::Send( const SfPacket* pPacket )
{
    SF_STATUS status = SF_STATUS_FAIL;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        status = SfSendPacket( m_pNode, pPacket );
    }
    m_pRWlock->Unlock();

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::Receive()
{
    SF_STATUS status = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        int ret = nl_recvmsgs_default( m_pNode->pHandle );
        if ( ret )
        {
            SF_LOG_E( "recv msg failed: %d(%s);", ret, nl_geterror(ret));
            status = SF_STATUS_FAIL;
        }
    }
    m_pRWlock->Unlock();

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::JoinGroup( Int32 group ) const
{
    SF_STATUS status = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        if ( nl_socket_add_membership( m_pNode->pHandle, group ) )
        {
            SF_LOG_E( "[joining group(%d) failed];", group );
            status = SF_STATUS_FAIL;
        }
    }
    m_pRWlock->Unlock();

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::LeaveGroup( Int32 group ) const
{
    SF_STATUS status = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        if ( nl_socket_drop_membership( m_pNode->pHandle, group ) )
        {
            SF_LOG_E( "[leaving group(%d)];", group );
            status = SF_STATUS_FAIL;
        }
    }
    m_pRWlock->Unlock();

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::SetReceiveBufferSize( Uint32 size )
{
    SF_STATUS status = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        if ( nl_socket_set_buffer_size( m_pNode->pHandle, size, 0 ) )
        {
            SF_LOG_E( "[setting buffer size(%u)(%s)];",
                      size, SF_GET_SYSTEM_ERROR(errno) );
            status = SF_STATUS_FAIL;
        } else {
            SF_LOG_E( "[set buffer size(%u)];", size);
        }
    }
    m_pRWlock->Unlock();

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::GetReceiveBufferSize( Uint32& size ) const
{
    socklen_t optLength = sizeof( Int32 );
    SF_STATUS status = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        const Int sockFd = nl_socket_get_fd( m_pNode->pHandle );
        if ( getsockopt( sockFd, SOL_SOCKET, SO_RCVBUF, &size, &optLength) < 0 )
        {
            SF_LOG_I("Getting needed size failed:%s;", SF_GET_SYSTEM_ERROR(errno));
            status = SF_STATUS_FAIL;
        }
    }
    m_pRWlock->Unlock();

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfNetlinkSocket::IsConnected() const
{
    m_pRWlock->ReadLock();
    Bool result = ( NULL == m_pNode ) ? FALSE : TRUE;
    m_pRWlock->Unlock();

    return result;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::CreateSocket()
{
    SF_STATUS result = SF_STATUS_OK;
    m_pRWlock->WriteLock();
    if( NULL == m_pNode )
        result = SfCreateNode(&m_pNode, "FIRE", 0xbedabeda);
    m_pRWlock->Unlock();

    return result;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::GetSocketName()
{
    socklen_t addrLength = sizeof( struct sockaddr_nl );
    SF_STATUS result = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        const Int sockFd = nl_socket_get_fd( m_pNode->pHandle );
        if ( SF_FAILED( getsockname( sockFd, (sockaddr*)m_pNode->pHandle, &addrLength ) ) ||
             addrLength != sizeof( struct sockaddr_nl ) )
        {
            SF_LOG_E( "[getsockname failed, err(%d)(%s)];",
                      errno, SF_GET_SYSTEM_ERROR(errno) );
            result = SF_STATUS_FAIL;
        }
    }
    m_pRWlock->Unlock();

    return result;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::SetNonBlocking()
{
    SF_STATUS status = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        if ( nl_socket_set_nonblocking( m_pNode->pHandle ) )
        {
            SF_LOG_E( "[fcntl failed, reason(%s)];", SF_GET_SYSTEM_ERROR( errno ) );
            status = SF_STATUS_FAIL;
        }
    }
    m_pRWlock->Unlock();

    return status;
}
