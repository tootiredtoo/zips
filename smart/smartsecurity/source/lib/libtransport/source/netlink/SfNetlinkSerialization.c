
#include "netlink/SfNetlinkSerialization.h"
#include "libcore/SfDebug.h"

#if defined(SF_LEVEL_USER)
    #include "netlink/netlink.h"
    #include "netlink/genl/genl.h"
    #include "netlink/genl/ctrl.h"
    #include "netlink/genl/mngt.h"
#else
    #include <net/sock.h>
#endif  /* !SF_LEVEL_USER */

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfNetlinkPacket* SfCreateNetlinkPacket(void)
{
    SfNetlinkPacket* pPacket = malloc( sizeof(SfNetlinkPacket) );
    if ( NULL != pPacket )
    {
#if defined(SF_LEVEL_USER)
        pPacket->pBuffer = nlmsg_alloc();
#else
        pPacket->pBuffer = nlmsg_new( NLMSG_DEFAULT_SIZE, GFP_ATOMIC );
#endif  /* !SF_LEVEL_USER */

        if ( NULL == pPacket->pBuffer )
        {
            SF_LOG_E( "[netlink-allocating failed];" );
            sf_free( pPacket );
            pPacket = NULL;
        }
    }
    else
    {
        SF_LOG_E( "[allocating failed];" );
    }
    return pPacket;
}
#if defined(SF_LEVEL_KERNEL)
EXPORT_SYMBOL(SfCreateNetlinkPacket)
#endif  // SF_LEVEL_KERNEL

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfDestroyNetlinkPacket(SfNetlinkPacket* const pPacket)
{
    if ( pPacket )
    {
        nlmsg_free( pPacket->pBuffer );
        free( pPacket );
        malloc_trim(0);
    }
}
#if defined(SF_LEVEL_KERNEL)
EXPORT_SYMBOL(SfDestroyNetlinkPacket)
#endif  // SF_LEVEL_KERNEL
