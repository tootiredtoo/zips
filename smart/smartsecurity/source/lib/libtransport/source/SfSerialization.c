
#include "SfSerialization.h"

#include "libtransport/SfNetlink.h"
#include "SfProtocolHeaderSerialization.h"
#include "SfPacketEnvironmentSerialization.h"
#include "SfPacketOperationSerialization.h"

#if defined(SF_LEVEL_USER)
	#include "netlink/attr.h"
	#include "netlink/netlink.h"
	#include "netlink/genl/genl.h"
	#include "netlink/genl/ctrl.h"
	#include "netlink/genl/mngt.h"
#else
	#include <net/sock.h>
#endif	// SF_LEVEL_USER

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfNetlinkPacket* SfSerializePacket( const SfPacket* pPacket )
{
    SfNetlinkPacket* pNPacket = NULL;
    struct nlattr* pAttr = NULL;
    
    do
    {
#if defined(SF_LEVEL_KERNEL)
        struct nlmsghdr* msgHdr = NULL;
#endif  // SF_LEVEL_KERNEL
        if ( !pPacket )
        {
            SF_LOG_E( "Incoming packet is NULL" );
            break;
        }

        pNPacket = SfCreateNetlinkPacket();
        if ( !pNPacket )
        {
            SF_LOG_E( "Failed to create Netlink packet" );
            break;
        }

#if defined(SF_LEVEL_KERNEL)
        msgHdr = nlmsg_put( pNPacket->pBuffer, 0, 0, SF_PACKET_TYPE_NOTIFICATION, 0, 0 );
#else
        nlmsg_put( pNPacket->pBuffer, 0, 0, SF_PACKET_TYPE_NOTIFICATION, 0, 0 );
#endif  // SF_LEVEL_KERNEL

        // serialize protocol header
        if ( SF_FAILED( SfSerializeProtocolHeader( &pPacket->header, pNPacket,
                                                   SFD_PACKET_HEADER_ATTR ) ) )
        {
            SF_LOG_E( "Failed to serialize protocol header" );
            SfDestroyNetlinkPacket( pNPacket );
            pNPacket = NULL;
            break;
        }

        // serialize packet environment if present
        if ( pPacket->env &&
             SF_FAILED( SfSerializePacketEnvironment( pPacket->env, pNPacket,
                                                      SFD_PACKET_ENVIRONMENT_ATTR ) ) )
        {
            SF_LOG_E( "Failed to serialize packet environment" );
            SfDestroyNetlinkPacket( pNPacket );
            pNPacket = NULL;
            break;
        }

        // serialize packet operation if present
        if ( pPacket->op &&
             SF_FAILED( SfSerializePacketOperation( pPacket->op, pNPacket,
                                                    SFD_PACKET_OPERATION_ATTR ) ) )
        {
            SF_LOG_E( "Failed to serialize packet operation" );
            SfDestroyNetlinkPacket( pNPacket );
            pNPacket = NULL;
            break;
        }

        pAttr = nla_nest_start( pNPacket->pBuffer, SFD_PACKET_VERSION_ATTR | NLA_F_NESTED );
        if ( pAttr )
        {
            nla_put_u32( pNPacket->pBuffer, SFD_PACKET_VERSION_NUMBER_ATTR, SF_PACKET_PROTOCOL_VERSION );
            nla_nest_end( pNPacket->pBuffer, pAttr );
        } 

#if defined(SF_LEVEL_KERNEL)
        nlmsg_end( pNPacket->pBuffer, msgHdr );
#endif  // SF_LEVEL_KERNEL
    }
    while ( FALSE );
    return pNPacket;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfPacket* SfDeserializePacket( const SfNetlinkPacket* pNPacket )
{
    SfPacket* pPacket = NULL;
    do
    {
        struct nlattr* packetAttrs [ SFD_PACKET_MAX_ATTR + 1 ] = { 0 };
        struct nlattr* versionAttrs [ SFD_PACKET_VERSION_MAX_ATTR + 1 ] = { 0 };
        struct nlattr* headerAttr = NULL, *envAttr = NULL, *opAttr = NULL, *verAttr = NULL;
        struct nlmsghdr* msgHdr = NULL;

        if ( !pNPacket )
        {
            SF_LOG_E( "Incoming Netlink packet is NULL" );
            break;
        }

        // load SfPacket Netlink attributes from Netlink message
        msgHdr = nlmsg_hdr( pNPacket->pBuffer );
        if ( nlmsg_parse( msgHdr, 0, packetAttrs, SFD_PACKET_MAX_ATTR, NULL ) )
        {
            SF_LOG_E( "Failed to parse Netlink attributes" );
            break;
        }

        // create packet
        pPacket = malloc( sizeof( SfPacket ) );
        if ( !pPacket )
        {
            SF_LOG_E( "Filed to allocate SfPacket structure" );
            break;
        }
        memset( pPacket, 0, sizeof( SfPacket ) );

        headerAttr   = packetAttrs[ SFD_PACKET_HEADER_ATTR ];
        envAttr      = packetAttrs[ SFD_PACKET_ENVIRONMENT_ATTR ];
        opAttr       = packetAttrs[ SFD_PACKET_OPERATION_ATTR ];
        verAttr      = packetAttrs[ SFD_PACKET_VERSION_ATTR ];
        // header attribute must be always present
        if ( !headerAttr )
        {
            SF_LOG_E( "Packet header attribute missing" );
            SfDestroyPacket( pPacket );
            pPacket = NULL;
            break;
        }
        if ( SF_FAILED( SfDeserializeProtocolHeader( &pPacket->header, headerAttr ) ) )
        {
            SF_LOG_E( "Failed to deserialize packet header" );
            SfDestroyPacket( pPacket );
            pPacket = NULL;
            break;
        }

        // deserialize environment if present
        if ( envAttr )
        {
            pPacket->env = SfDeserializePacketEnvironment( envAttr );
            if ( !pPacket->env )
            {
                SF_LOG_E( "Failed to deserialize packet environment" );
                SfDestroyPacket( pPacket );
                pPacket = NULL;
                break;
            }
        }

        // deserialize operation if present
        if ( opAttr )
        {
            pPacket->op = SfDeserializePacketOperation( opAttr );
            if ( !pPacket->op )
            {
                SF_LOG_E( "Failed to deserialize packet operation" );
                SfDestroyPacket( pPacket );
                pPacket = NULL;
                break;
            }
        }

        // deserialize  sf netlink version attribute
        if (verAttr)
        {
            if ( !nla_parse_nested( versionAttrs, SFD_PACKET_VERSION_MAX_ATTR, verAttr, NULL ) )
            {
                struct nlattr* versionAttr = versionAttrs[ SFD_PACKET_VERSION_NUMBER_ATTR ];
                if ( versionAttr )
                {
                    pPacket->version = nla_get_u32( versionAttr );
                }
            }   
        }
    }
    while ( FALSE );
    return pPacket;
}
