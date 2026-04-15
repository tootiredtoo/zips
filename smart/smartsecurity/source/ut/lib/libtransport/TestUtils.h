#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include "libprotocol/SfOperationsFormat.h"
#include "libprotocol/SfEnvironmentFormat.h"

bool EqualProtocolHeader( const SfProtocolHeader* pHdrA, const SfProtocolHeader* pHdrB );

bool EqualOperationBlockRule( const SfOperationBlockRule* pRuleA,
                              const SfOperationBlockRule* pRuleB );

bool EqualOperationSetupDUID( const SfOperationSetupDUID* pDuidA,
                              const SfOperationSetupDUID* pDuidB );

bool EqualExecEnvironment( const SfExecutionEnvironmentInfo* pEnvA,
                           const SfExecutionEnvironmentInfo* pEnvB );

bool EqualFileEnvironment( const SfFileEnvironment* pEnvA, const SfFileEnvironment* pEnvB );

bool EqualProcessEnvironment( const SfProcessEnvironment* pEnvA,
                              const SfProcessEnvironment* pEnvB );

bool EqualNetworkEnvironment( const SfNetworkEnvironment* pEnvA,
                              const SfNetworkEnvironment* pEnvB );

bool EqualMmapEnvironment( const SfMmapEnvironment* pEnvA, const SfMmapEnvironment* pEnvB );

#endif  // TEST_UTILS_H