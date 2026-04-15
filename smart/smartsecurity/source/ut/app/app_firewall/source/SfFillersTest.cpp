/**
****************************************************************************************************
* @file SfFillersTest.cpp
* @brief Security framework [SF] implementation:
* @brief unit test for class data_translation/fillers/SfFillers.h
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jul 14, 2014 09:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
// local
#include "SfFillersTest.h"

// project
#include "filters/SfFilterBase.h"
#include "data_translation/fillers/SfFillers.h"
#include "data_translation/json/SfJSONNode.h"
#include "libcore/SfMemory.h"
#include "SfTags.h"

/**
****************************************************************************************************
* @brief Adds the specified fixture suite to the unnamed registry
****************************************************************************************************
*/
CPPUNIT_TEST_SUITE_REGISTRATION( SfFillersTest );

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static const std::string c_procNameValue    = "/bin/cat";
static const std::string c_fileValue        = "/home/file";
static const Uint64      c_inodeValue       = 2048;
static const Uint64      c_timeValue        = 48;
static const Uint32      c_addrValue        = 1024;
static const Uint32      c_pidValue         = 42;
static const Uint32      c_resultValue      = 0;
static const Uint16      c_portValue        = 8080;
static const std::string c_actionValue      = "LOG";

static const std::string c_openEventJSON    = "{\"open\":{\"process\":\"/bin/cat\",\"pid\":42,"\
"\"result\":0,\"time\":48,\"file\":\"/home/file\",\"inode\":2048}}";

static const std::string c_procEventJSON    = "{\"exec\":{\"process\":\"/bin/cat\",\"pid\":42,"\
"\"result\":0,\"time\":48,\"process\":\"/home/file\",\"pid\":2048}}";

static const std::string c_connectEventJSON = "{\"connect\":{\"process\":\"/bin/cat\",\"pid\":42,"\
"\"result\":0,\"time\":48,\"addr\":1024,\"port\":8080}}";

static const std::string c_configJSON       = "{\"recLimit\":100,\"sendTimeout\":"\
"10000,\"sendCounter\":1,\"sendOverflow\":true}";

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfFillersTest::SfFillersTest()
{

}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfFillersTest::~SfFillersTest()
{
}

/**
****************************************************************************************************
//@sut      TestFillJSONString
//@brief    Fill environment setting from each filter
****************************************************************************************************
*/

void SfFillersTest::TestFillFilters()
{
    TestFillFileEnvFilter1();
    TestFillFileEnvFilter2();
    TestFillProcEnvFilter1();
    TestFillProcEnvFilter2();
}

/**
****************************************************************************************************
//@sut      TestFillJSONString
//@brief    Fill json string from each filter
****************************************************************************************************
*/

void SfFillersTest::TestFillJSONString()
{
    TestFillJSONStringBySfFileEnv();
    TestFillJSONStringBySfProcEnv();
    TestFillJSONStringBySfNetEnv();
}

/**
****************************************************************************************************
//@sut      TestFillSfConfig
//@brief    Firewall Set Config Test
****************************************************************************************************
*/

void SfFillersTest::TestFillSfConfig()
{
    SfSCSConfig::SfConfig configEtalon;
    configEtalon.recLimit       = 100;
    configEtalon.sendCounter    = 1;
    configEtalon.sendOverflow   = true;
    configEtalon.sendTimeOut    = 10000;

    SfJSONNode configNode( c_tagConfig );
    SfSCSConfig::SfConfig config;
    EXPECT_EQ( SF_SUCCESS( configNode.Parse( c_configJSON ) ) , 0 );
    EXPECT_EQ( SF_SUCCESS( Fill( &configNode, config ) ) , 0  );
    CPPUNIT_ASSERT( configEtalon.recLimit       == config.recLimit );
    CPPUNIT_ASSERT( configEtalon.sendTimeOut    == config.sendTimeOut );
}

/**
****************************************************************************************************
//@sut      TestFillFileEnvFilter1
//@brief    Fill File Filter Rule
****************************************************************************************************
*/

void SfFillersTest::TestFillFileEnvFilter1()
{
    SfJSONNode openEventNode;
    openEventNode.Put( c_tagProcName,       c_procNameValue );
    openEventNode.Put( c_tagFileName,       c_fileValue );
    openEventNode.Put( c_tagInode,          c_inodeValue );
    openEventNode.Put( c_tagSysCallResult,  c_resultValue );
    openEventNode.Put( c_tagAction,         c_actionValue );

    TestFillFileEnvFilter( openEventNode );
}

/**
****************************************************************************************************
//@sut      TestFillFileEnvFilter2
//@brief    Fill File Filter None Rule
****************************************************************************************************
*/

void SfFillersTest::TestFillFileEnvFilter2()
{
    SfJSONNode openEventNode;
    openEventNode.Put( c_tagProcName,       c_tagAsterisk );
    openEventNode.Put( c_tagFileName,       c_tagAsterisk );
    openEventNode.Put( c_tagInode,          c_asteriskU64 );
    openEventNode.Put( c_tagSysCallResult,  c_asteriskS32);
    openEventNode.Put( c_tagAction,         c_tagAsterisk );

    TestFillFileEnvFilter( openEventNode );
}

/**
****************************************************************************************************
//@sut      TestFillFileEnvFilter
//@brief    Set File Filter Rule
//@input    SfJSONNode Json file item
****************************************************************************************************
*/

void SfFillersTest::TestFillFileEnvFilter( SfJSONNode& openEventNode )
{
    SfFileEnvironment fileEnv = SF_INIT_SFFILE_ENVIRONMENT;
    FillDefault( fileEnv );

    SfPacket packet = SF_INIT_SFPACKET;
    packet.env = (SfEnvironmentHeader*)&fileEnv;
    SfFilterBase* pFilter = NULL;
    EXPECT_EQ( SF_SUCCESS( Fill( &openEventNode, SFD_OPEN_EVENT_GRP, pFilter ) ) , 0 );
    CPPUNIT_ASSERT( NULL != pFilter );
    EXPECT_EQ( SF_SUCCESS( pFilter->Match( packet ) ) , 0 );

    SF_DELETE_ARRAY fileEnv.processContext.pProcessName;
    SF_DELETE_ARRAY fileEnv.pFileName;
}

/**
****************************************************************************************************
//@sut      TestFillProcEnvFilter1
//@brief    Fill Porcess Rule
****************************************************************************************************
*/

void SfFillersTest::TestFillProcEnvFilter1()
{
    SfJSONNode procEventNode;
    procEventNode.Put( c_tagProcName,       c_procNameValue );
    procEventNode.Put( c_tagFileName,       c_fileValue );
    procEventNode.Put( c_tagInode,          c_inodeValue );
    procEventNode.Put( c_tagSysCallResult,  c_resultValue );
    procEventNode.Put( c_tagAction,         c_actionValue );

    TestFillProcEnvFilter( procEventNode );
}

/**
****************************************************************************************************
//@sut      TestFillProcEnvFilter2
//@brief    Fill Process None Rule
****************************************************************************************************
*/

void SfFillersTest::TestFillProcEnvFilter2()
{
    SfJSONNode procEventNode;
    procEventNode.Put( c_tagProcName,       c_tagAsterisk );
    procEventNode.Put( c_tagFileName,       c_tagAsterisk );
    procEventNode.Put( c_tagInode,          c_asteriskU64 );
    procEventNode.Put( c_tagSysCallResult,  c_asteriskS32);
    procEventNode.Put( c_tagAction,         c_tagAsterisk );

    TestFillProcEnvFilter( procEventNode );
}

/**
****************************************************************************************************
//@sut      TestFillProcEnvFilter
//@brief    Set Process Filter Rule
//@input    SfJSONNode Json file item
****************************************************************************************************
*/

void SfFillersTest::TestFillProcEnvFilter( SfJSONNode& procEventNode )
{
    SfProcessEnvironment procEnv = SF_INIT_SFPROCESS_ENVIRONMENT;
    FillDefault( procEnv );

    SfPacket packet = SF_INIT_SFPACKET;
    packet.env = (SfEnvironmentHeader*)&procEnv;
    SfFilterBase* pFilter = NULL;
    EXPECT_EQ( SF_SUCCESS( Fill( &procEventNode, SFD_EXEC_EVENT_GRP, pFilter ) ) , 0 );
    CPPUNIT_ASSERT( NULL != pFilter );
    EXPECT_EQ( SF_SUCCESS( pFilter->Match( packet ) ) , 0 );

    SF_DELETE_ARRAY procEnv.processContext.pProcessName;
    SF_DELETE_ARRAY procEnv.pProcessName;
}

/**
****************************************************************************************************
//@sut      TestFillJSONStringBySfFileEnv
//@brief    Set Json file Rule from File Filter Environment
****************************************************************************************************
*/

void SfFillersTest::TestFillJSONStringBySfFileEnv()
{
    std::string json;
    SfPacket packet             = SF_INIT_SFPACKET;
    SfFileEnvironment fileEnv   = SF_INIT_SFFILE_ENVIRONMENT;
    FillDefault( fileEnv );
    packet.env = (SfEnvironmentHeader*)&fileEnv;

    EXPECT_EQ( SF_SUCCESS( Fill( packet, json ) ) , 0 );
    CPPUNIT_ASSERT( c_openEventJSON == json );
}

/**
****************************************************************************************************
//@sut      TestFillJSONStringBySfFileEnv
//@brief    Set Json file Rule from Process Filter Environment
****************************************************************************************************
*/

void SfFillersTest::TestFillJSONStringBySfProcEnv()
{
    std::string json;
    SfPacket packet              = SF_INIT_SFPACKET;
    SfProcessEnvironment procEnv = SF_INIT_SFPROCESS_ENVIRONMENT;
    FillDefault( procEnv );
    packet.env = (SfEnvironmentHeader*)&procEnv;

    EXPECT_EQ( SF_SUCCESS( Fill( packet, json ) ) , 0 );
    CPPUNIT_ASSERT( c_procEventJSON == json );
}

/**
****************************************************************************************************
//@sut      TestFillJSONStringBySfFileEnv
//@brief    Set Json file Rule from Network Filter Environment
****************************************************************************************************
*/

void SfFillersTest::TestFillJSONStringBySfNetEnv()
{
    std::string json;
    SfPacket packet             = SF_INIT_SFPACKET;
    SfNetworkEnvironment netEnv = SF_INIT_SFNETWORK_ENVIRONMENT;
    FillDefault( netEnv );
    packet.env = (SfEnvironmentHeader*)&netEnv;

    EXPECT_EQ( SF_SUCCESS( Fill( packet, json ) ) , 0 );
    CPPUNIT_ASSERT( c_connectEventJSON == json );
}

/**
****************************************************************************************************
//@sut      FillFileDefault
//@brief    Fill Default File Rule Set
//@input    SfFileEnvironment File Environment
****************************************************************************************************
*/

void SfFillersTest::FillDefault( SfFileEnvironment& fileEnv )
{
    const size_t sizeProc = c_procNameValue.length() + 1;
    const size_t sizeFile = c_fileValue.length() + 1;
    fileEnv.processContext.pProcessName = SF_NEW_ARRAY Char[ sizeProc ];
    fileEnv.pFileName                   = SF_NEW_ARRAY Char[ sizeFile ];
    sf_memcpy( fileEnv.processContext.pProcessName, c_procNameValue.c_str(), sizeProc );
    sf_memcpy( fileEnv.pFileName, c_fileValue.c_str(), sizeFile );
    fileEnv.processContext.processId        = c_pidValue;
    fileEnv.processContext.sysCallResult    = c_resultValue;
    fileEnv.processContext.timeStamp        = c_timeValue;
    fileEnv.inode                           = c_inodeValue;
}

/**
****************************************************************************************************
//@sut      FillProcessDefault
//@brief    Fill Default Process Rule Set    
//@input    SfProcessEnvironment Process Environment
****************************************************************************************************
*/

void SfFillersTest::FillDefault( SfProcessEnvironment& procEnv )
{
    const size_t sizeProc = c_procNameValue.length() + 1;
    const size_t sizeFile = c_fileValue.length() + 1;
    procEnv.processContext.pProcessName = SF_NEW_ARRAY Char[ sizeProc ];
    procEnv.pProcessName                = SF_NEW_ARRAY Char[ sizeFile ];
    sf_memcpy( procEnv.processContext.pProcessName, c_procNameValue.c_str(), sizeProc );
    sf_memcpy( procEnv.pProcessName, c_fileValue.c_str(), sizeFile );
    procEnv.processContext.processId        = c_pidValue;
    procEnv.processContext.sysCallResult    = c_resultValue;
    procEnv.processContext.timeStamp        = c_timeValue;
    procEnv.processImageId                  = c_inodeValue;
}

/**
****************************************************************************************************
//@sut      FillNetworkDefault
//@brief    Fill Default Network Rule Set    
//@input    SfNetworkEnvironment Network Environment
****************************************************************************************************
*/

void SfFillersTest::FillDefault( SfNetworkEnvironment& netEnv )
{
    const size_t sizeProc = c_procNameValue.length() + 1;
    netEnv.processContext.pProcessName = SF_NEW_ARRAY Char[ sizeProc ];
    sf_memcpy( netEnv.processContext.pProcessName, c_procNameValue.c_str(), sizeProc );
    netEnv.processContext.processId        = c_pidValue;
    netEnv.processContext.sysCallResult    = c_resultValue;
    netEnv.processContext.timeStamp        = c_timeValue;
    netEnv.port                            = c_portValue;
    netEnv.addr                            = c_addrValue;
}
