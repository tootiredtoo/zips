/**
****************************************************************************************************
* @file SfNetlinkUser.c
* @brief Security framework [SF] filter driver [D] Implementation of the Netlink transport
*   mechanisms for user space modules
* @author Dmitriy Dorogovtsev(d.dorogovtse@samsung.com)
* @author Maksym Koshel (m.koshel@samsung.com)
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created May 23, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#define SF_MOD_CLASS SF_DEBUG_CLASS_TRP
#include "libcore/SfDebug.h"

#include "SfTransport.h"
#include "SfSerialization.h"

#include "netlink/netlink.h"
#include "netlink/genl/genl.h"
#include "netlink/genl/ctrl.h"
#include "netlink/genl/mngt.h"

#include <unistd.h>
#include <sys/socket.h>

/*
****************************************************************************************************
*
****************************************************************************************************
*/
static SfNode* SfAllocateNode(void)
{
    SfNode* pNode = NULL;

    // Allocate memory for the Security Framework node structure
    pNode = malloc(sizeof(SfNode));
    if (NULL != pNode)
    {
        // Clear memory
        memset(pNode, 0x00, sizeof(SfNode));

        // Allocate new netlink socket using libnl API
        pNode->pHandle = nl_socket_alloc();

        /**
        * @brief Check allocation result. In case if libnl nl_socket_alloc function will return NULL
        *   pointer it is necessary to free memory that was allocated for communication node (pNode)
        */
        if (NULL == pNode->pHandle)
        {
            sf_free(pNode);
            pNode = NULL;
        }
    }

    return pNode;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
static void SfFreeNode(SfNode* const pNode)
{
    if (pNode != NULL)
    {
        if (NULL != pNode->pHandle)
        {
            nl_socket_free(pNode->pHandle);
        }
        free(pNode);
        malloc_trim(0);
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS SfRegisterNode(SfNode* const pNode)
{
    SF_STATUS result = SF_STATUS_FAIL;

    do
    {
        if (NULL == pNode)
        {
            SF_LOG_E("[invalid param];");
            result = SF_STATUS_BAD_ARG;
            break;
        }

        int nlRes = nl_connect(pNode->pHandle, SF_PROTOCOL_NUMBER);

        if (0 == nlRes)
        {
            result = SF_STATUS_OK;
        }
        else
        {
            SF_LOG_E("[connecting by using netlink failed(%d)];", nlRes);
            result = SF_STATUS_FAIL;
        }

    } while(FALSE);

    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS SfUnregisterNode(SfNode* const pNode)
{
    SF_STATUS result = SF_STATUS_OK;

    if (NULL != pNode)
    {
        nl_close(pNode->pHandle);
    }

    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SFAPI SfCreateNode(SfNode** ppNode, const Char* const name, Ulong id)
{
    SF_STATUS result = SF_STATUS_FAIL;

    SfNode* pNode = NULL;

    do
    {
        if (NULL == ppNode || NULL == name)
        {
            SF_LOG_E("[invalid param];");
            result = SF_STATUS_BAD_ARG;
            break;
        }

        pNode = SfAllocateNode();
        if (NULL == pNode)
        {
            SF_LOG_E("[Can not allocate node];");
            break;
        }

        sf_strncpy(pNode->id.name, name, sizeof(pNode->id.name) - 1);
        pNode->id.name[sizeof(pNode->id.name) - 1] = 0;
        pNode->id.magic = id;

        result = SfRegisterNode(pNode);
        if (SF_FAILED(result))
        {
            SfFreeNode(pNode);
            break;
        }

        *ppNode = pNode;

    } while(FALSE);

    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SFAPI SfDestroyNode(SfNode* const pNode)
{
    SF_STATUS result = SF_STATUS_FAIL;
    result = SfUnregisterNode(pNode);
    SfFreeNode(pNode);
    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SFAPI SfSendPacket(SfNode* const pNode, const SfPacket* const pPacket)
{
    SF_STATUS result = SF_STATUS_FAIL;

    do
    {
        if ( NULL == pNode || NULL == pPacket ) ///< NULL == pPacket is temporary (disable warning)
        {
            SF_LOG_E("[invalid param];");
            result = SF_STATUS_NOT_IMPLEMENTED;
            break;
        }

        SfNetlinkPacket* pNetlinkPacket = SfSerializePacket( pPacket );
        if ( !pNetlinkPacket )
        {
            SF_LOG_E( "[Failed to serialize packet];" );
            break;
        }

        // specify destination to kernel
        struct sockaddr_nl nlAddr = { AF_NETLINK, 0, 0, 0 };
        nlmsg_set_dst( pNetlinkPacket->pBuffer, &nlAddr );
        int nlRes = nl_send_auto(pNode->pHandle, pNetlinkPacket->pBuffer);

        if (nlRes < 0)
        {
            SF_LOG_E("[netlink sending failed(%d)];", nlRes);
            result = SF_STATUS_FAIL;
            SfDestroyNetlinkPacket(pNetlinkPacket);
            break;
        }
        result = SF_STATUS_OK;
        SfDestroyNetlinkPacket(pNetlinkPacket);
    } while(FALSE);

    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SFAPI SfReceivePacket(SfNode* const pNode, SfPacket** const pPacket)
{
    SF_STATUS result = SF_STATUS_NOT_IMPLEMENTED;

    do
    {
        if ( NULL == pNode || NULL == pPacket ) ///< NULL == pPacket is temporary (disable warning)
        {
            SF_LOG_E("[invalid param];");
            result = SF_STATUS_NOT_IMPLEMENTED;
            break;
        }

    } while(FALSE);

    return result;
}
