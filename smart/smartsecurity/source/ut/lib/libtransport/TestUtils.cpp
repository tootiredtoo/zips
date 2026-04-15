#include "TestUtils.h"

//--------------------------------------------------------------------------------------------------

bool EqualProtocolHeader( const SfProtocolHeader* pHdrA, const SfProtocolHeader* pHdrB )
{
    return ( pHdrA->size == pHdrB->size ) && ( pHdrA->type == pHdrB->type );
}

//--------------------------------------------------------------------------------------------------

bool EqualOperationBlockRule( const SfOperationBlockRule* pRuleA,
                              const SfOperationBlockRule* pRuleB )
{
    return EqualProtocolHeader( &pRuleA->header, &pRuleB->header ) &&
           ( pRuleA->ruleType == pRuleB->ruleType ) &&
           ( pRuleA->action == pRuleB->action ) &&
           ( pRuleA->ipAddr == pRuleB->ipAddr ) &&
           ( pRuleA->fileInode == pRuleB->fileInode );
}

//--------------------------------------------------------------------------------------------------

bool EqualOperationSetupDUID( const SfOperationSetupDUID* pDuidA,
                              const SfOperationSetupDUID* pDuidB )
{
    return EqualProtocolHeader( &pDuidA->header, &pDuidB->header ) &&
           ( 0 == strcmp( pDuidA->pDUID, pDuidB->pDUID ) );
}

//--------------------------------------------------------------------------------------------------

bool EqualExecEnvironment( const SfExecutionEnvironmentInfo* pEnvA,
                           const SfExecutionEnvironmentInfo* pEnvB )
{
    if (!pEnvB->pProcessName)
    {
        return false;
    }
    return ( pEnvA->processId == pEnvB->processId ) &&
           ( pEnvA->sysCallResult == pEnvB->sysCallResult ) &&
           ( pEnvA->timeStamp == pEnvB->timeStamp ) &&
           ( 0 == strcmp( pEnvA->pProcessName, pEnvB->pProcessName ) );

}

//--------------------------------------------------------------------------------------------------

bool EqualFileEnvironment( const SfFileEnvironment* pEnvA, const SfFileEnvironment* pEnvB )
{
    return EqualProtocolHeader( &pEnvA->header, &pEnvB->header ) &&
           EqualExecEnvironment( &pEnvA->processContext, &pEnvB->processContext ) &&
           ( 0 == strcmp( pEnvA->pFileName, pEnvB->pFileName ) ) &&
           ( pEnvA->inode == pEnvB->inode );
}

//--------------------------------------------------------------------------------------------------

bool EqualProcessEnvironment( const SfProcessEnvironment* pEnvA,
                              const SfProcessEnvironment* pEnvB )
{
    return EqualProtocolHeader( &pEnvA->header, &pEnvB->header ) &&
           EqualExecEnvironment( &pEnvA->processContext, &pEnvB->processContext ) &&
           ( 0 == strcmp( pEnvA->pProcessName, pEnvB->pProcessName ) ) &&
           ( pEnvA->processImageId == pEnvB->processImageId );
}

//--------------------------------------------------------------------------------------------------

bool EqualNetworkEnvironment( const SfNetworkEnvironment* pEnvA,
                              const SfNetworkEnvironment* pEnvB )
{
    return EqualProtocolHeader( &pEnvA->header, &pEnvB->header ) &&
           EqualExecEnvironment( &pEnvA->processContext, &pEnvB->processContext ) &&
           ( pEnvA->addr == pEnvB->addr ) &&
           ( pEnvA->port == pEnvB->port );
}

//--------------------------------------------------------------------------------------------------

bool EqualMmapEnvironment( const SfMmapEnvironment* pEnvA, const SfMmapEnvironment* pEnvB )
{
    return EqualProtocolHeader( &pEnvA->header, &pEnvB->header ) &&
           EqualExecEnvironment( &pEnvA->processContext, &pEnvB->processContext ) &&
           ( 0 == strcmp( pEnvA->pLibraryName, pEnvB->pLibraryName ) ) &&
           ( pEnvA->inode == pEnvB->inode );
}

//--------------------------------------------------------------------------------------------------
