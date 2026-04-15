//! \file       unix_socket.cpp
//! \brief      Class UnixSocket implementation.
//! \author     Dmitriy Dorogovtsev (d.dorogovtse@samsung.com), Anton Skakun (a.skakun@samsung.com)
//! \version    0.1
//! \date       Created Jun 5, 2013
//! \par        In Samsung Ukraine R&D Center (SRK) under a contract between
//! \par        LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine) and
//! \par        "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
//! \copyright  Samsung Electronics Co, Ltd 2013. All rights reserved.

#include "UnixSocket.h"

#include <vector>

#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define SOCKET_TIMEOUT 5

const Int32 UnixSocket::s_badDescriptor = -1;

/**
****************************************************************************************************
* @brief                    Waits for read/write event on file descriptor
* @param [in] dcsr          File descriptor to monitor
* @param [in] msec          Minimum poll() timeout in milliseconds. If 0, will return immediately
* @param [in] reading       If true, descriptor is monitored for reading; if false, for writing
* @return                   SF_STATUS_OK if descriptor is ready for requested operation,
*   SF_STATUS_FAIL otherwise
****************************************************************************************************
*/
static SF_STATUS SfDescriptorReadyForOperation( Int32 descriptor, Uint32 mSec, Bool reading )
{
    if ( descriptor < 0 )
    {
        SfSleepMs( mSec );
        return SF_STATUS_FAIL;
    }

    struct timeval timeout;
    timeout.tv_sec = (long)(mSec / 1000);
    timeout.tv_usec = (long)((mSec % 1000) * 1000);

    fd_set dSet;
    FD_ZERO( &dSet );
    FD_SET( descriptor, &dSet );
    if ( reading )
    {
        return ( select( descriptor + 1, &dSet, NULL, NULL, &timeout ) > 0 ) ?
               SF_STATUS_OK : SF_STATUS_FAIL;
    }
    else
    {
        return ( select( descriptor + 1, NULL, &dSet, NULL, &timeout ) > 0 ) ?
               SF_STATUS_OK : SF_STATUS_FAIL;
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
UnixSocket::UnixSocket()
    : m_socketDescriptor( s_badDescriptor )
{
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
UnixSocket::~UnixSocket()
{
    Disconnect();
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::SetupHost( const char* hostName, Uint32 maxConnections )
{
    SF_STATUS r = SF_STATUS_FAIL;
    SetupSocket( hostName );
    do
    {
        if ( SF_FAILED( CreateSocketDescriptor() ) )
        {
            break;
        }
        if ( SF_FAILED( Bind() ) )
        {
            break;
        }
        r = Listen( maxConnections );
    }
    while ( FALSE );
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::AcceptConnection( UnixSocket& remoteSocket )
{
    struct linger   ling;
    socklen_t addrLength = sizeof( sockaddr_un );
    remoteSocket.m_socketDescriptor = ::accept( m_socketDescriptor,
                                                (sockaddr*)&remoteSocket.m_socketStruct,
                                                &addrLength );
    if ( -1 == remoteSocket.m_socketDescriptor )
    {
        SF_LOG_E( "accept() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        return SF_STATUS_FAIL;
    }
    
    ling.l_onoff = 1;
    ling.l_linger = 0;      /* 0 for abortive disconnect */
    setsockopt(remoteSocket.m_socketDescriptor, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::AcceptConnection( UnixSocket& remoteSocket, Uint32 msec, Bool silent )
{
    if ( !IsReadyForReading( msec ) )
    {
        if ( !silent )
            SF_LOG_I( "timeout(%d msec);", msec );
        return SF_STATUS_FAIL;
    }

    return AcceptConnection( remoteSocket );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::ConnectToHost(const char* remoteHostName)
{
    SetupSocket(remoteHostName);
    if (SF_FAILED(CreateSocketDescriptor()))
    {
        return SF_STATUS_FAIL;
    }

    Int32 lr = ::connect(m_socketDescriptor, (sockaddr*)&m_socketStruct, sizeof(sockaddr_un));
    if ( lr < 0 )
    {
        SF_LOG_E( "connect() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::ConnectToHostNonBlocking(const char* remoteHostName)
{
    SF_LOG_I( "called;");

    SetupSocket(remoteHostName);
    if (SF_FAILED(CreateSocketDescriptor()))
    {
        return SF_STATUS_FAIL;
    }

    if (SetNonBlocking() == SF_STATUS_FAIL)
    {
        return SF_STATUS_FAIL;
    }

    Int32 lr = ::connect(m_socketDescriptor, (sockaddr*)&m_socketStruct, sizeof(sockaddr_un));
    if ( lr < 0 )
    {
        SF_LOG_E( "connect() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        return SF_STATUS_FAIL;
    }
    
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(m_socketDescriptor, &writeSet);
    
    struct timeval tval;
    tval.tv_sec = SOCKET_TIMEOUT;
    tval.tv_usec = 0;

    if (select(m_socketDescriptor+1, NULL, &writeSet, NULL, &tval) == 0)
    {
        SF_LOG_E( "connect() timeout;");
        return SF_STATUS_FAIL;
    }
    
    if (FD_ISSET(m_socketDescriptor, &writeSet) <= 0)
    {
        SF_LOG_E( "m_socketDescriptor is not set;");
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::Disconnect()
{
    SF_STATUS r = SF_STATUS_OK;
    if ( m_socketDescriptor >= 0 )
    {
        const Int32 res = ::close( m_socketDescriptor );
        m_socketDescriptor = s_badDescriptor;
        r = ( res == 0 ) ? SF_STATUS_OK : SF_STATUS_FAIL;
    }
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::SetNonBlocking()
{
    SF_STATUS r = SF_STATUS_OK;
    if ( fcntl( m_socketDescriptor, F_SETFL, O_NONBLOCK ) == -1 )
    {
        SF_LOG_E( "fcntl() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        r = SF_STATUS_FAIL;
    }
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::IsConnected() const
{
    return ( m_socketDescriptor != s_badDescriptor );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::SendString( const std::string& message )
{
    Bool r = FALSE;
    Uint32 length = message.size();
    if ( SendData( (Uint8*)&length, sizeof(Uint32) ) )
    {
        r = SendData( (const Uint8*)message.c_str(), length + 1 );
    }
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::ReceiveString( std::string& message )
{
    Bool r = FALSE;
    Uint32 length = 0;
    if ( ReceiveData( (Uint8*)&length, sizeof(Uint32) ) )
    {
        std::vector< Uint8 > buf( length + 1, 0 );
        if ( ReceiveData( &buf[ 0 ], length + 1 ) )
        {
            message = std::string( (const char*)&buf[ 0 ] );
            r = TRUE;
        }
    }
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::ReceiveString( std::string& message, Uint32 msec )
{
    return ( IsReadyForReading( msec ) ) ? ReceiveString( message ) : FALSE;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::IsReadyForReading( Uint32 msec ) const
{
    return ( SfDescriptorReadyForOperation( m_socketDescriptor, msec, TRUE ) == SF_STATUS_OK );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::IsReadyForWriting( Uint32 msec ) const
{
    return ( SfDescriptorReadyForOperation( m_socketDescriptor, msec, FALSE ) == SF_STATUS_OK );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::Bind()
{
    SF_STATUS r = SF_STATUS_OK;
    if ( -1 == ::bind( m_socketDescriptor, (sockaddr*)&m_socketStruct, sizeof( sockaddr_un ) ) )
    {
        SF_LOG_E( "bind() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        r = SF_STATUS_FAIL;
    }
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::Listen( Uint32 maxConnections )
{
    SF_STATUS r = SF_STATUS_OK;
    if ( -1 == ::listen( m_socketDescriptor, maxConnections ) )
    {
        SF_LOG_E( "listen() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        r = SF_STATUS_FAIL;
    }
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void UnixSocket::SetupSocket( const char* socketName )
{
    memset( &m_socketStruct, 0, sizeof( sockaddr_un ) );
    m_socketStruct.sun_family = AF_UNIX;
    strncpy( m_socketStruct.sun_path + 1, socketName, sizeof( m_socketStruct.sun_path ) - 1 );
    m_socketStruct.sun_path[ 0 ] = 0; // abstract name
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::SendData( const Uint8* data, Uint32 length )
{
    Bool r = TRUE;
    while ( length )
    {
        const ssize_t sr = send( m_socketDescriptor, data, length, MSG_NOSIGNAL );
        if ( sr < 0 )
        {
            SF_LOG_E( "send() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
            Disconnect();
            r = FALSE;
            break;
        }
        data    += sr;
        length  -= sr;
    }
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool UnixSocket::ReceiveData( Uint8* data, Uint32 length )
{
    Bool ret = TRUE;
    while ( length )
    {
        const ssize_t c_result = recv( m_socketDescriptor, data, length, 0 );
        if ( c_result > 0 )
        {
            data    += c_result;
            length  -= c_result;
            continue;
        }

        if ( c_result < 0 )
        {
            SF_LOG_E( "recv() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        }
        else
        {
            SF_LOG_W( "peer is shutdown;" );
        }

        Disconnect();
        ret = FALSE;
        break;
    }
    return ret;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS UnixSocket::CreateSocketDescriptor()
{
    SF_STATUS r = SF_STATUS_OK;    
    struct linger   ling;
    
    m_socketDescriptor = socket( AF_UNIX, SOCK_STREAM, 0 );
    if ( 0 > m_socketDescriptor )
    {
        SF_LOG_E( "socket() error = %s;", SF_GET_SYSTEM_ERROR( errno ) );
        m_socketDescriptor = s_badDescriptor;
        r = SF_STATUS_FAIL;
    }
    
    ling.l_onoff = 1;
    ling.l_linger = 0;      /* 0 for abortive disconnect */
    setsockopt(m_socketDescriptor, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    return r;
}
