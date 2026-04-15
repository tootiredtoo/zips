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
 * NETLINK_NO_ENOBUFS suppresses ENOBUFS errors caused by kernel-side receive buffer overruns.
 * Without this option, when the kernel drops messages due to a full socket buffer, the next
 * nl_recvmsgs_default() call returns -EIO (-5) rather than succeeding or blocking.
 * Available since Linux 2.6.30.
 */
#ifndef NETLINK_NO_ENOBUFS
    #define NETLINK_NO_ENOBUFS 5
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
            /* Suppress kernel ENOBUFS signals so receive-loop overruns don't
             * look like hard failures.  Non-fatal if unsupported by the kernel. */
            EnableNoEnobufs();

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
            /**
             * Error -5 (EIO / "Input/output error") from nl_recvmsgs_default() is caused by
             * ENOBUFS from the kernel: the netlink socket receive buffer overflowed and the
             * kernel silently dropped one or more messages before this recv call.
             *
             * This is NOT an out-of-memory condition (the colleague analysis confuses
             * NLE_NOMEM=5 with NLE_IO=5; nl_geterror() for a raw -EIO returns the POSIX
             * strerror(5) string "Input/output error", not the libnl "Out of memory" string).
             *
             * The correct response is:
             *   - Log a warning (security events were lost — this is noteworthy but recoverable).
             *   - Return SF_STATUS_OVERRUN so the caller can decide whether to reconnect/resync.
             *   - Do NOT retry blind recv calls: the overrun is already past; there is no
             *     buffered data to drain here.
             *
             * Longer-term prevention is handled by:
             *   1. Setting NETLINK_NO_ENOBUFS on the socket (done in SetNonBlocking() /
             *      a new EnableNoEnobufs() call from Connect()) so the kernel suppresses the
             *      EIO signal and userspace keeps receiving subsequent messages without
             *      interruption.
             *   2. Using SO_RCVBUFFORCE in SetReceiveBufferSize() so the 7 MB request is not
             *      silently capped by /proc/sys/net/core/rmem_max.
             */
            if ( ret == -EIO || ret == -ENOBUFS )
            {
                SF_LOG_W( "recv msg overrun (kernel dropped messages): %d(%s); "
                          "security events may have been lost;", ret, nl_geterror(ret) );
                status = SF_STATUS_OVERRUN;
            }
            else
            {
                SF_LOG_E( "recv msg failed: %d(%s);", ret, nl_geterror(ret) );
                status = SF_STATUS_FAIL;
            }
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
        const Int sockFd = nl_socket_get_fd( m_pNode->pHandle );

        /**
         * Use SO_RCVBUFFORCE (Linux 2.6.14+) so the requested 7 MB buffer is not silently
         * capped by /proc/sys/net/core/rmem_max (often ~208 KB on Tizen builds).
         * nl_socket_set_buffer_size() wraps plain SO_RCVBUF, which is subject to that cap —
         * the kernel accepts the call without error but applies a smaller value, so the
         * subsequent GetReceiveBufferSize() warning fires and the buffer stays small,
         * leading to ENOBUFS overruns under event bursts.
         * sfpmd runs as a VIP process with CAP_NET_ADMIN, so SO_RCVBUFFORCE should succeed.
         * Fall back to SO_RCVBUF if it does not (e.g., running without elevated caps).
         */
#ifndef SO_RCVBUFFORCE
    #define SO_RCVBUFFORCE 33
#endif
        Int optVal = static_cast<Int>( size );
        if ( setsockopt( sockFd, SOL_SOCKET, SO_RCVBUFFORCE, &optVal, sizeof(optVal) ) < 0 )
        {
            SF_LOG_W( "[SO_RCVBUFFORCE(%u) failed(%s), falling back to SO_RCVBUF];",
                      size, SF_GET_SYSTEM_ERROR(errno) );

            if ( nl_socket_set_buffer_size( m_pNode->pHandle, size, 0 ) )
            {
                SF_LOG_E( "[setting buffer size(%u)(%s)];",
                          size, SF_GET_SYSTEM_ERROR(errno) );
                status = SF_STATUS_FAIL;
            }
            else
            {
                SF_LOG_I( "[set buffer size(%u) via SO_RCVBUF];", size );
            }
        }
        else
        {
            SF_LOG_I( "[set buffer size(%u) via SO_RCVBUFFORCE];", size );
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

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfNetlinkSocket::EnableNoEnobufs()
{
    /**
     * Set NETLINK_NO_ENOBUFS (Linux 2.6.30+) on the netlink socket.
     *
     * Without this option, when the kernel's per-socket receive buffer overflows it
     * signals ENOBUFS on the next recvmsg() call.  libnl3 converts that to -EIO (-5),
     * which the log shows as "recv msg failed: -5(Input/output error)".  The overrun has
     * already happened at that point — the missed messages cannot be recovered — but the
     * EIO makes the entire Receive() call appear to have failed, breaking the receive loop.
     *
     * With NETLINK_NO_ENOBUFS set the kernel suppresses the signal: subsequent recv calls
     * succeed normally (returning the next available message) so the receive loop continues
     * uninterrupted.  Messages lost during the overrun are still gone, but the framework
     * keeps running rather than reporting a hard failure on every burst.
     *
     * The overrun root cause (buffer too small or consumption too slow) is addressed
     * separately by SetReceiveBufferSize() using SO_RCVBUFFORCE.
     */
    SF_STATUS status = SF_STATUS_OK;
    m_pRWlock->ReadLock();
    if( NULL != m_pNode )
    {
        const Int sockFd = nl_socket_get_fd( m_pNode->pHandle );
        const Int optVal = 1;
        if ( setsockopt( sockFd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &optVal, sizeof(optVal) ) < 0 )
        {
            SF_LOG_W( "[NETLINK_NO_ENOBUFS failed(%s)]; overrun errors may still surface;",
                      SF_GET_SYSTEM_ERROR(errno) );
            /* Non-fatal: the socket still works; overrun handling in Receive() covers this. */
        }
        else
        {
            SF_LOG_I( "[NETLINK_NO_ENOBUFS enabled on socket];" );
        }
    }
    m_pRWlock->Unlock();

    return status;
}
