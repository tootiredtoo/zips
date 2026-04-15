/**
****************************************************************************************************
* @file SfNetlinkSocket.h
* @brief Security framework [SF] wrap netlink socket functions
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created May 16, 2014 17:00.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_NETLINK_SOCKET_H_
#define _SF_NETLINK_SOCKET_H_

// project
#include "libtransport/SfTransport.h"
#include "libprimitive/SfRWLock.h"
#include "netlink/socket.h"

/**
****************************************************************************************************
* @class SfNetlinkSocket
* @brief Wrap netlink socket
****************************************************************************************************
*/
class SfNetlinkSocket
{
public: // methods
    SfNetlinkSocket();
    SfNetlinkSocket( const SfNetlinkSocket& );
    ~SfNetlinkSocket();

    SF_STATUS Connect( Uint8 retriesCount, Ulong timeOutMs,
                       nl_recvmsg_msg_cb_t callback, void* arg );
    SF_STATUS ReadyForRead( __suseconds_t timeOutMicroSec ) const;
    SF_STATUS Send( const SfPacket* pPacket );
    SF_STATUS Receive();
    SF_STATUS JoinGroup( Int32 group ) const;
    SF_STATUS LeaveGroup( Int32 group ) const;
    SF_STATUS SetReceiveBufferSize( Uint32 size );
    SF_STATUS GetReceiveBufferSize( Uint32& size ) const;
    Bool IsConnected() const;

private: // methods
    SF_STATUS CreateSocket();
    SF_STATUS BindSocket();
    SF_STATUS GetSocketName();
    SF_STATUS SetNonBlocking();
    const SfNetlinkSocket operator = (const SfNetlinkSocket& ); //blocked

private: // members
    SfRWLock * m_pRWlock;
    SfNode* m_pNode;

}; // class SfNetlinkSocket;

#endif /* _SF_NETLINK_SOCKET_H_ */
