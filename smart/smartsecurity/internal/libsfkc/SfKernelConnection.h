/**
****************************************************************************************************
* @vd_noapi
* @file SfKernelConnection.h
* @brief Security framework [SF] receive message from kernel
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created May 28, 2014 09:39
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_KERNEL_CONNECTION_H_
#define _SF_KERNEL_CONNECTION_H_

// project
#include "libcore/SfCore.h"
#include "libprotocol/SfPacket.h"

// system
#include <vector>

/**
****************************************************************************************************
*
****************************************************************************************************
*/
class SfNetlinkSocket;

class SfKernelConnection
{
private: // methods
    SfKernelConnection( const SfKernelConnection& rhs );
    SfKernelConnection& operator=( const SfKernelConnection& rhs );

public: // methods
    SfKernelConnection();
    ~SfKernelConnection();

    SF_STATUS Connect();
    SF_STATUS ReadyForRead( __suseconds_t timeOutMicroSec ) const;
    SF_STATUS JoinGroup( SF_OPERATION_TYPE group );
    SF_STATUS LeaveGroup( SF_OPERATION_TYPE group );
    SF_STATUS Receive( SfPacket*& pPacket );
    SF_STATUS Send( const SfPacket* pPacket );
    SF_STATUS SetupNetworkRule( Uint32 addr );
    SF_STATUS SetupOpenRule( Uint64 inode );
    SF_STATUS DeleteAllRules();
    SF_STATUS SetupSndRcvRule( SfPacket& packet );
    void SetPacket( SfPacket* pPacket );
    Bool IsConnected() const;

private: // methods
    SF_STATUS EstablishKernelConnection();
    SF_STATUS SetupSocketBuffSize();

private: // members
    SfNetlinkSocket* m_pSocket;
    SfPacket*        m_pPacket;

}; // class SfKernelConnection

#endif /* _SF_KERNEL_CONNECTION_H_ */
