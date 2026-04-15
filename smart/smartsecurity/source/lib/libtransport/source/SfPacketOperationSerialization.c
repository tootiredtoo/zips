#include "SfPacketOperationSerialization.h"
#include "SfProtocolHeaderSerialization.h"
#include "SfNetlink.h"

#include "libprotocol/SfOperationsFormat.h"
#include "libprotocol/SfPacket.h"

#if defined(SF_LEVEL_USER)
    #include <netlink/attr.h>
#else
    #include <net/sock.h>
#endif  // SF_LEVEL_USER

#if defined(SF_LEVEL_KERNEL)
/**
****************************************************************************************************
*
****************************************************************************************************
*/
static Char* nla_strdup( struct nlattr* pAttr )
{
    Char* out = NULL, *data = NULL;
    data = (Char*)( nla_data( pAttr ) );
    if ( data )
    {
        Uint length = strlen( data ) + 1;
        out = malloc( length );
        if ( out )
        {
            memcpy( out, data, length );
        }
    }
    return out;
}
#endif  // SF_LEVEL_KERNEL

#if defined(SF_LEVEL_USER)
/*
****************************************************************************************************
*
****************************************************************************************************
*/
static int32_t nla_get_s32( struct nlattr* nla )
{
    return *(int32_t*)nla_data( nla );
}
#endif  // SF_LEVEL_USER

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS PutOperationRule( const SfProtocolHeader* pHeader, SfNetlinkPacket* pPacket,
                                   Int attribute )
{
    SF_STATUS r = SF_STATUS_FAIL;
    const SfOperationBlockRule* pOp = (const SfOperationBlockRule*)pHeader;

    struct nlattr* pAttr = nla_nest_start( pPacket->pBuffer, attribute | NLA_F_NESTED );
    if ( pAttr )
    {
        if ( !nla_put_u32( pPacket->pBuffer, SFD_OP_RULE_TYPE_ATTR, pOp->ruleType ) &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_RULE_ACTION_ATTR, pOp->action ) &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_RULE_ADDR_ATTR, pOp->ipAddr )   &&
             !nla_put_u64( pPacket->pBuffer, SFD_OP_RULE_INODE_ATTR, pOp->fileInode ) )
        {
            r = SF_STATUS_OK;
        }
        nla_nest_end( pPacket->pBuffer, pAttr );
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS LoadOperationRule( SfOperationBlockRule* pOp, struct nlattr* pAttribute )
{
    SF_STATUS r = SF_STATUS_FAIL;

    struct nlattr* opAttrs [ SFD_OP_RULE_MAX_ATTR + 1 ] = { 0 };
    if ( !nla_parse_nested( opAttrs, SFD_OP_RULE_MAX_ATTR, pAttribute, NULL ) )
    {
        struct nlattr* typeAttr   = opAttrs[ SFD_OP_RULE_TYPE_ATTR ];
        struct nlattr* actionAttr = opAttrs[ SFD_OP_RULE_ACTION_ATTR ];
        struct nlattr* addrAttr   = opAttrs[ SFD_OP_RULE_ADDR_ATTR ];
        struct nlattr* inodeAttr  = opAttrs[ SFD_OP_RULE_INODE_ATTR ];

        if ( typeAttr && actionAttr && addrAttr && inodeAttr )
        {
            pOp->ruleType  = nla_get_u32( typeAttr );
            pOp->action    = nla_get_u32( actionAttr );
            pOp->ipAddr    = nla_get_u32( addrAttr );
            pOp->fileInode = nla_get_u64( inodeAttr );
            r = SF_STATUS_OK;
        }
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS PutOperationSetupDUID( const SfProtocolHeader* pHeader, SfNetlinkPacket* pPacket,
                                        Int attribute )
{
    SF_STATUS r = SF_STATUS_FAIL;
    const SfOperationSetupDUID* pOp = (const SfOperationSetupDUID*)pHeader;

    struct nlattr* pAttr = nla_nest_start( pPacket->pBuffer, attribute | NLA_F_NESTED );
    if ( pAttr )
    {
        if ( !nla_put_string( pPacket->pBuffer, SFD_OP_DUID_DUID_ATTR, pOp->pDUID ) )
        {
            r = SF_STATUS_OK;
        }
        nla_nest_end( pPacket->pBuffer, pAttr );
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS LoadOperationSetupDUID( SfOperationSetupDUID* pOp, struct nlattr* pAttribute )
{
    SF_STATUS r = SF_STATUS_FAIL;

    struct nlattr* opAttrs [ SFD_OP_DUID_MAX_ATTR + 1 ] = { 0 };
    if ( !nla_parse_nested( opAttrs, SFD_OP_DUID_MAX_ATTR, pAttribute, NULL ) )
    {
        struct nlattr* duidAttr = opAttrs[ SFD_OP_DUID_DUID_ATTR ];
        if ( duidAttr )
        {
            pOp->pDUID = nla_strdup( duidAttr );
            r = SF_STATUS_OK;
        }
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS PutOperationFwRule( const SfProtocolHeader* pHeader, SfNetlinkPacket* pPacket,
                                     Int attribute )
{
    SF_STATUS r = SF_STATUS_FAIL;
    const SfOperationFwRule* pOp = (const SfOperationFwRule*)pHeader;

    struct nlattr* pAttr = nla_nest_start( pPacket->pBuffer, attribute | NLA_F_NESTED );
    if ( pAttr )
    {
        if ( !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_PROTOCOL_ATTR, pOp->rule.protocol )   &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_DIRECTION_ATTR, pOp->rule.direction ) &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_IP_FTYPE_ATTR, pOp->rule.ipFType )    &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_IP_ATYPE_ATTR, pOp->rule.ipAType )    &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_IP_V0_ATTR, pOp->rule.ip[ 0 ] )       &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_IP_V1_ATTR, pOp->rule.ip[ 1 ] )       &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_PORT_FTYPE_ATTR,
                           pOp->rule.portFType )                                                  &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_PORT_ATYPE_ATTR,
                           pOp->rule.portAType )                                                  &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_PORT_V0_ATTR, pOp->rule.port[ 0 ] )   &&
             !nla_put_u32( pPacket->pBuffer, SFD_OP_FW_RULE_PORT_V1_ATTR, pOp->rule.port[ 1 ] ) )
        {
            r = SF_STATUS_OK;
        }
        nla_nest_end( pPacket->pBuffer, pAttr );
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS LoadOperationFwRule( SfOperationFwRule* pOp, struct nlattr* pAttribute )
{
    SF_STATUS r = SF_STATUS_FAIL;

    struct nlattr* opAttrs [ SFD_OP_FW_RULE_MAX_ATTR + 1 ] = { 0 };
    if ( !nla_parse_nested( opAttrs, SFD_OP_FW_RULE_MAX_ATTR, pAttribute, NULL ) )
    {
        struct nlattr* protoAttr     = opAttrs[ SFD_OP_FW_RULE_PROTOCOL_ATTR ];
        struct nlattr* dirAttr       = opAttrs[ SFD_OP_FW_RULE_DIRECTION_ATTR ];
        struct nlattr* ipFTypeAttr   = opAttrs[ SFD_OP_FW_RULE_IP_FTYPE_ATTR ];
        struct nlattr* ipATypeAttr   = opAttrs[ SFD_OP_FW_RULE_IP_ATYPE_ATTR ];
        struct nlattr* ipV0Attr      = opAttrs[ SFD_OP_FW_RULE_IP_V0_ATTR ];
        struct nlattr* ipV1Attr      = opAttrs[ SFD_OP_FW_RULE_IP_V1_ATTR ];
        struct nlattr* portFTypeAttr = opAttrs[ SFD_OP_FW_RULE_PORT_FTYPE_ATTR ];
        struct nlattr* portATypeAttr = opAttrs[ SFD_OP_FW_RULE_PORT_ATYPE_ATTR ];
        struct nlattr* portV0Attr    = opAttrs[ SFD_OP_FW_RULE_PORT_V0_ATTR ];
        struct nlattr* portV1Attr    = opAttrs[ SFD_OP_FW_RULE_PORT_V1_ATTR ];

        if ( protoAttr && dirAttr && ipFTypeAttr && ipATypeAttr && ipV0Attr && ipV1Attr &&
             portFTypeAttr && portATypeAttr && portV0Attr && portV1Attr )
        {
            pOp->rule.protocol  = nla_get_u32( protoAttr );
            pOp->rule.direction = nla_get_u32( dirAttr );
            pOp->rule.ipFType   = nla_get_u32( ipFTypeAttr );
            pOp->rule.ipAType   = nla_get_u32( ipATypeAttr );
            pOp->rule.ip[ 0 ]   = nla_get_u32( ipV0Attr );
            pOp->rule.ip[ 1 ]   = nla_get_u32( ipV1Attr );
            pOp->rule.portFType = nla_get_u32( portFTypeAttr );
            pOp->rule.portAType = nla_get_u32( portATypeAttr );
            pOp->rule.port[ 0 ] = nla_get_u32( portV0Attr );
            pOp->rule.port[ 1 ] = nla_get_u32( portV1Attr );
            r = SF_STATUS_OK;
        }
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS LoadSendReportInfo( SfOperationSecurityReport* pOp, struct nlattr* pAttribute )
{
    SF_STATUS r = SF_STATUS_FAIL;

    struct nlattr* opAttrs [ SFD_OP_REPORT_MAX_ATTR__ + 1 ] = { 0 };
    if ( !nla_parse_nested( opAttrs, SFD_OP_REPORT_MAX_ATTR__, pAttribute, NULL ) )
    {
        struct nlattr* callerAttr      = opAttrs[ SFD_OP_REPORT_CALLER_ATTR ];
        struct nlattr* filetypeAttr    = opAttrs[ SFD_OP_REPORT_FILETYPE_ATTR ];
        struct nlattr* filepathAttr    = opAttrs[ SFD_OP_REPORT_FILEPATH_ATTR ];
        struct nlattr* descAttr        = opAttrs[ SFD_OP_REPORT_DESC_ATTR ];
        struct nlattr* flagAttr        = opAttrs[ SFD_OP_REPORT_SENDFLAG_ATTR ];
        struct nlattr* autodataAttr    = opAttrs[ SFD_OP_REPORT_AUTO_DATA_ATRR ];
        struct nlattr* descsizeAttr    = opAttrs[ SFD_OP_REPORT_DESC_SIZE ];
        struct nlattr* descpartcntAttr = opAttrs[ SFD_OP_REPORT_DESC_PART_CNT ];
        struct nlattr* descpartseqAttr = opAttrs[ SFD_OP_REPORT_DESC_PART_SEQ ];
        struct nlattr* desctimeAttr    = opAttrs[ SFD_OP_REPORT_DESC_SYS_TIME ];

        if ( callerAttr && filetypeAttr && filepathAttr && descAttr &&
             descsizeAttr && descpartcntAttr && descpartseqAttr && desctimeAttr )
        {
            pOp->caller      = nla_strdup( callerAttr );
            if (pOp->caller) 
            {
                SF_LOG_I("caller:%s;", pOp->caller);
            }
            pOp->filetype    = nla_strdup( filetypeAttr );
            if (pOp->filetype)
            {
                SF_LOG_I("type:%s;", pOp->filetype);
            }
            pOp->filepath    = nla_strdup( filepathAttr );
            if (pOp->filepath) 
            {
                SF_LOG_I("path:%s;", pOp->filepath);
            }
            pOp->description = nla_strdup( descAttr );
            if (pOp->description) 
            {
                SF_LOG_I("desc:%s;", pOp->description);
            }
            pOp->sendfileflag = nla_get_s32( flagAttr );
            pOp->autodatafile     = nla_get_s32( autodataAttr );
            pOp->descriptionsize = nla_get_s32( descsizeAttr );
            pOp->desc_partial_cnt = nla_get_s32( descpartcntAttr );
            pOp->desc_partial_seq = nla_get_s32( descpartseqAttr );
            SF_LOG_I("[%d,%d, %d,%d,%d];", 
                pOp->sendfileflag, pOp->autodatafile, pOp->descriptionsize, pOp->desc_partial_cnt, pOp->desc_partial_seq);
            pOp->desc_time = nla_strdup( desctimeAttr );
            if (pOp->desc_time) 
            {
                SF_LOG_I("[time:%s]", pOp->desc_time);
            }
            r = SF_STATUS_OK;
        }
    }
    return r;
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS SerializeOperationRule( const SfProtocolHeader* pHeader, SfNetlinkPacket* pPacket,
                                         Int attribute )
{
    SF_STATUS r = SF_STATUS_FAIL;

    struct nlattr* pAttr = nla_nest_start( pPacket->pBuffer, attribute | NLA_F_NESTED );
    if ( pAttr )
    {
        if ( SF_SUCCESS(SfSerializeProtocolHeader( pHeader, pPacket, SFD_OP_HEADER_ATTR )) &&
             SF_SUCCESS(PutOperationRule( pHeader, pPacket, SFD_OP_DATA_ATTR )) )
        {
            r = SF_STATUS_OK;
        }
        nla_nest_end( pPacket->pBuffer, pAttr );
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS SerializeOperationSetupDUID( const SfProtocolHeader* pHeader,
                                              SfNetlinkPacket* pPacket, Int attribute )
{
    SF_STATUS r = SF_STATUS_FAIL;

    struct nlattr* pAttr = nla_nest_start( pPacket->pBuffer, attribute | NLA_F_NESTED );
    if ( pAttr )
    {
        if ( SF_SUCCESS(SfSerializeProtocolHeader( pHeader, pPacket, SFD_OP_HEADER_ATTR )) &&
             SF_SUCCESS(PutOperationSetupDUID( pHeader, pPacket, SFD_OP_DATA_ATTR )) )
        {
            r = SF_STATUS_OK;
        }
        nla_nest_end( pPacket->pBuffer, pAttr );
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SF_STATUS SerializeOperationFwRule( const SfProtocolHeader* pHeader,
                                           SfNetlinkPacket* pPacket, Int attribute )
{
    SF_STATUS r = SF_STATUS_FAIL;

    struct nlattr* pAttr = nla_nest_start( pPacket->pBuffer, attribute | NLA_F_NESTED );
    if ( pAttr )
    {
        if ( SF_SUCCESS(SfSerializeProtocolHeader( pHeader, pPacket, SFD_OP_HEADER_ATTR )) &&
             SF_SUCCESS(PutOperationFwRule( pHeader, pPacket, SFD_OP_DATA_ATTR )) )
        {
            r = SF_STATUS_OK;
        }
        nla_nest_end( pPacket->pBuffer, pAttr );
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfSerializePacketOperation( const SfProtocolHeader* pHeader,
                                      SfNetlinkPacket* pNetlinkPacket, Int attribute )
{
    SF_STATUS r = SF_STATUS_FAIL;
    if ( !pHeader || !pNetlinkPacket )
    {
        return SF_STATUS_BAD_ARG;
    }

    switch ( pHeader->type )
    {
        case SF_OPERATION_TYPE_RULE:
            r = SerializeOperationRule( pHeader, pNetlinkPacket, attribute );
            break;

        case SF_OPERATION_TYPE_SETUP_DUID:
            r = SerializeOperationSetupDUID( pHeader, pNetlinkPacket, attribute );
            break;

        case SF_OPERATION_TYPE_SND_RCV_RULE:
            r = SerializeOperationFwRule( pHeader, pNetlinkPacket, attribute );
            break;
        case SF_OPERATION_TYPE_REPORT_NET:     /* fall through */
        case SF_OPERATION_TYPE_REPORT_PROCESS: /* fall through */
        case SF_OPERATION_TYPE_REPORT_FILE:
            break;

        default:
            // this is hack to send packets with event notifications to userspace
            // because packet in kernel contains operation with LSM arguments that
            // can not be serialized
            r = SF_STATUS_OK;
            break;
    }
    return r;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SfProtocolHeader* DeserializeOperation( const SfProtocolHeader* opHeader,
                                               struct nlattr* opDataAttr )
{
    SfProtocolHeader* pHeader = NULL;

    switch ( opHeader->type )
    {
        case SF_OPERATION_TYPE_RULE:
        {
            SfOperationBlockRule* pRuleOp = 
                SF_CREATE_OPERATION( SfOperationBlockRule, SF_OPERATION_TYPE_RULE );
            if (pRuleOp)
            {
                pRuleOp->header = *opHeader;
                LoadOperationRule( pRuleOp, opDataAttr );
                pHeader = (SfProtocolHeader*)pRuleOp;
            }
            break;
        }

        case SF_OPERATION_TYPE_SETUP_DUID:
        {
            SfOperationSetupDUID* pDuidOp = 
                SF_CREATE_OPERATION( SfOperationSetupDUID, SF_OPERATION_TYPE_SETUP_DUID );
            if (pDuidOp)
            {
                pDuidOp->header = *opHeader;
                LoadOperationSetupDUID( pDuidOp, opDataAttr );
                pHeader = (SfProtocolHeader*)pDuidOp;
            }
            break;
        }

        case SF_OPERATION_TYPE_SND_RCV_RULE:
        {
            SfOperationFwRule* pFwRuleOp = 
                SF_CREATE_OPERATION( SfOperationFwRule, SF_OPERATION_TYPE_SND_RCV_RULE );
            if (pFwRuleOp)
            {
                pFwRuleOp->header = *opHeader;
                LoadOperationFwRule( pFwRuleOp, opDataAttr );
                pHeader = (SfProtocolHeader*)pFwRuleOp;
            }
            break;
        }

        case SF_OPERATION_TYPE_REPORT_NET:     /* fall through */
        case SF_OPERATION_TYPE_REPORT_PROCESS: /* fall through */
        case SF_OPERATION_TYPE_REPORT_FILE:
        {
            SfOperationSecurityReport* pReportOp = 
                SF_CREATE_OPERATION( SfOperationSecurityReport, SF_OPERATION_TYPE_REPORT_NET );
            if (pReportOp)
            {
                pReportOp->header = *opHeader;
                LoadSendReportInfo( pReportOp, opDataAttr );
                pHeader = (SfProtocolHeader*)pReportOp;
            }
            break;
        }

        default:
            SF_LOG_E( "[unsupported op type(%d)];", opHeader->type );
            break;
    }
    return pHeader;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfProtocolHeader* SfDeserializePacketOperation( struct nlattr* pAttribute )
{
    SfProtocolHeader* pHeader = NULL;
    struct nlattr* opAttrs [ SFD_OP_MAX_ATTR + 1 ] = { 0 };

    if ( !pAttribute )
    {
        return NULL;
    }
    if ( !nla_parse_nested( opAttrs, SFD_OP_MAX_ATTR, pAttribute, NULL ) )
    {
        struct nlattr* headerAttr = opAttrs[ SFD_OP_HEADER_ATTR ];
        struct nlattr* dataAttr   = opAttrs[ SFD_OP_DATA_ATTR ];
        if ( headerAttr && dataAttr )
        {
            SfProtocolHeader opHeader;
            SfDeserializeProtocolHeader( &opHeader, headerAttr );
            pHeader = DeserializeOperation( &opHeader, dataAttr );
        }
    }
    return pHeader;
}