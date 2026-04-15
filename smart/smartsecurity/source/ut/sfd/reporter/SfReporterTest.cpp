/**
****************************************************************************************************
* @file SfReporterTest.cpp
* @test SfReporterTest.cpp
* @brief
* @author Namgwon Lee (namgwon.lee@samsung.com)
* @date Created JULY 21, 2016 09:00
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2016. All rights reserved.
****************************************************************************************************
*/

#include <string>
#include <cstdlib>
#include <dlfcn.h>
#include "common/SfTasksTags.h"
#include "SfTaskMessageReceiver.h"
#include <tzplatform_config.h>

// third party
#include <gtest/gtest.h>
#include <jsoncpp/json/json.h>

class ReporterTest : public ::testing::Test
{
protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
};

class ReporterAPI
{
public:
    int SendSecurityReport(const char * caller, const char* type, const char* path, const char* description, const int sendfileflag);
    std::string GetFormattedTime();
};

typedef int (*ReportPluginInterface)(const char *caller, const char *type, const char *path, const char *description, const int sendfileflag);
int ReporterAPI::SendSecurityReport(const char *caller, const char *type, const char *path, const char *description, const int sendfileflag)
{
    int ret = false;
    static ReportPluginInterface s_Reporter = NULL;
    if (0 == s_Reporter) {
        static void *s_pHandle = 0;
        if (0 == s_pHandle) {
            static const char *c_reporter_so = TZ_SYS_LIB"/libkUEPUser.so";
            s_pHandle = dlopen(c_reporter_so, RTLD_LAZY | RTLD_LOCAL);
            if (0 == s_pHandle) {
                printf("\e[1;31m[reporter] pHandle Error : %s\e[0m\n", dlerror());
                return ret;
            }
        }
        dlerror(); 

        static const char *s_report_func = "SendSecurityReport";
        s_Reporter = (ReportPluginInterface)dlsym(s_pHandle, s_report_func);

        char *error;
        if ((error = dlerror()) != NULL) {
            printf("\e[1;31m[reporter] dlsym Error : %s\e[0m\n", error);
            dlclose(s_pHandle);
            s_pHandle = 0;
            return ret;
        }
    }

    ret = s_Reporter(caller, type, path, description, sendfileflag);
    return ret;
}

std::string ReporterAPI::GetFormattedTime()
{
    char formattedTime[ 256 ] = { '\0' };
    time_t currentTime;
    struct tm newTime;

    currentTime = time(NULL);
    if ( NULL == localtime_r( &currentTime, &newTime ) )
    {
        SF_LOG_E( "localtime() failed, error = [%s];", SF_GET_SYSTEM_ERROR(errno) );
        return std::string();
    }

    if ( 0 == strftime( formattedTime, sizeof( formattedTime ), "%T", &newTime ) )
    {
        SF_LOG_E( "strftime() failed;" );
        return std::string();
    }
    return formattedTime;
}

static const char* Caller      = "Tester";
static const int Execution     = 1;
static const char* FileType    = "ELF";
static const char* Path        = "/usr/bin/sfpmd";
static const char* Description = "Not Signed";
static const char* Name        = "TestFile";

void freeReporterInfo( ReporterInfo* pReporterInfo )
{
    sf_free(pReporterInfo->ExtInfo.caller);
    sf_free(pReporterInfo->ExtInfo.fileType);
    sf_free(pReporterInfo->ExtInfo.fileName);
    sf_free(pReporterInfo->ExtInfo.fileHash);
    sf_free(pReporterInfo->ExtInfo.description);
}

/***************************************************************************************************
//@sut      vdapi_CheckNetworktStatus_p, ReporterTest
//@brief    Positive Test 1 for CheckNetworktStatus
//@input    None
***************************************************************************************************
*/
TEST ( ReporterTest, vdapi_CheckNetworktStatus_p )
{
    SfRecorder recorder;
    ASSERT_TRUE( SF_SUCCESS(recorder.checkNetworkStatus()) ) ;
}

TEST (ReporterTest, GetHashTest)
{
    std::string testfile = "/usr/bin/cat";
    int len = testfile.length();

    ReporterInfo Info;
    Info.ExtInfo.fileName = strndup(testfile.c_str(), len);
    Info.ExtInfo.fileNameLength = len;

    SfRecorder reportHandler;
    reportHandler.GetScsHash(&Info);
    std::string testHash = Info.ExtInfo.fileHash;
    SF_LOG_I("[TEST] [%s]Hash : %s",testfile.c_str(), testHash.c_str() );

    EXPECT_GT(Info.ExtInfo.fileHashLength, 0);

    len = strlen(Path);

    Info.ExtInfo.fileName = strndup(Path, len);
    Info.ExtInfo.fileNameLength = len;

    reportHandler.GetScsHash(&Info);
    std::string compareHash = Info.ExtInfo.fileHash;
    EXPECT_TRUE( testHash != compareHash);
}

/**
***************************************************************************************************
//@sut      vdapi_ComposeSecurityReport, ReporterTest
//@brief    Positive test for ComposeSecurityReport
//@input    Path Dummy Files
***************************************************************************************************
*/
TEST( ReporterTest, ClearSecurityReportDataFiles)
{
    const std::string reportDumyBaseDir = tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/data/report/");

    const std::string createBaseDir = std::string("mkdir -p ") + reportDumyBaseDir;
    int ret = std::system(createBaseDir.c_str());
    SF_LOG_I("[TEST]create base dir command: %s(%d)", createBaseDir.c_str(), ret);

    SF_LOG_I("[TEST]report path : %s",reportDumyBaseDir.c_str());
    std::string dummyFileName = "DATA_$i";
    std::string reportDummyFiles = reportDumyBaseDir;
    reportDummyFiles += dummyFileName;
    std::string command = "for((i = 0; i < 2000;i++)) do touch ";
    command += reportDummyFiles;
    command += "; done";

    ret = std::system(command.c_str());
    SF_LOG_I("[TEST]file create command: %s(%d)", command.c_str(), ret);

    SfFilesList subDir;
    SfFilesList datafiles;
    datafiles.clear();
    subDir.clear();

    if( !ListFolderContent(reportDumyBaseDir,datafiles,subDir)){
        SF_LOG_E("Fail to list up files in directory ;");
    }

    SF_LOG_I("[TEST]created file count: %zu", datafiles.size());

    EXPECT_GT(datafiles.size(), 0);

    SecurityReport::ReportTaskWorker taskworker;
    taskworker.Execute(SecurityReport::CLEAR);

    sleep(5);

    datafiles.clear();
    subDir.clear();
    if( !ListFolderContent(reportDumyBaseDir,datafiles,subDir)){
        SF_LOG_E("[TEST] Fail to list up files in directory ;");
    }
    EXPECT_EQ(datafiles.size(), 0);
}

/**
***************************************************************************************************
//@sut      DuplicateClearSecurityReportDataFiles, ReporterTest
//@brief    Positive test for ComposeSecurityReport
//@input    Path Dummy Files
***************************************************************************************************
*/
TEST( ReporterTest, DuplicateClearSecurityReportDataFiles)
{
    const std::string reportDumyBaseDir = tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/data/report/");
    
    const std::string createBaseDir = std::string("mkdir -p ") + reportDumyBaseDir;
    int ret = std::system(createBaseDir.c_str());
    SF_LOG_I("[TEST]create base dir command: %s(%d)", createBaseDir.c_str(), ret);
    
    SfFilesList subDir;
    SfFilesList datafiles;
    datafiles.clear();
    subDir.clear();

    SecurityReport::ReportTaskWorker taskworker;
    taskworker.Execute(SecurityReport::CLEAR);

    datafiles.clear();
    subDir.clear();
    if( !ListFolderContent(reportDumyBaseDir,datafiles,subDir)){
        SF_LOG_E("[TEST] Fail to list up files in directory ;");
    }
    EXPECT_EQ(datafiles.size(), 0);

    taskworker.Execute(SecurityReport::CLEAR);

    datafiles.clear();
    subDir.clear();
    if( !ListFolderContent(reportDumyBaseDir,datafiles,subDir)){
        SF_LOG_E("[TEST] Fail to list up files in directory ;");
    }
    EXPECT_EQ(datafiles.size(), 0);
}

TEST( ReporterTest, ClearCCLogFiles)
{
    const std::string cclogDumyBaseDir = "/opt/GAIA/logs/";
    SF_LOG_I("[TEST]report path : %s",cclogDumyBaseDir.c_str());
    std::string dummyFileName = "GAIA-$i";
    std::string reportDummyFiles = cclogDumyBaseDir;
    reportDummyFiles += dummyFileName;
    std::string command = "for((i = 0; i < 2000;i++)) do touch ";
    command += reportDummyFiles;
    command += "; done";

    const std::string createBaseDir = std::string("mkdir -p ") + cclogDumyBaseDir;
    int ret = std::system(createBaseDir.c_str());
    SF_LOG_I("[TEST]create base dir command: %s(%d)", createBaseDir.c_str(), ret);

    ret = std::system(command.c_str());
    SF_LOG_I("[TEST]file create command: %s(%d)", command.c_str(), ret);

    SfFilesList subDir;
    SfFilesList datafiles;
    datafiles.clear();
    subDir.clear();

    if( !ListFolderContent(cclogDumyBaseDir,datafiles,subDir)){
        SF_LOG_E("Fail to list up files in directory ;");
    }

    SF_LOG_I("[TEST]created file count: %zu", datafiles.size());

    EXPECT_GT(datafiles.size(), 0);

    SecurityReport::ReportTaskWorker taskworker;
    taskworker.Execute(SecurityReport::CCLOG_CLEAR);

    sleep(5);

    datafiles.clear();
    subDir.clear();
    if( !ListFolderContent(cclogDumyBaseDir,datafiles,subDir)){
        SF_LOG_E("[TEST] Fail to list up files in directory ;");
    }
    EXPECT_EQ(datafiles.size(), 0);
}

/**
***************************************************************************************************
//@sut      vdapi_ComposeSecurityReport_p, ReporterTest
//@brief    Positive test for ComposeSecurityReport
//@input    Caller, Execution, FileType, Path, Description
***************************************************************************************************
*/
TEST ( ReporterTest, vdapi_ComposeSecurityReport_p )
{
    ReporterInfo Info;
    SfTaskMessageReceiver* pInst = SfTaskMessageReceiver::GetInstance();
    if (pInst)
    {
        EXPECT_TRUE( SF_SUCCESS(
    	pInst->composeSecurityReport( Caller, 
    								  FileType, 
    								  Path, 
    								  Description, 
    								  Name, 
    								  &Info)
    	));
    }
}

/**
***************************************************************************************************
//@sut      vdapi_ComposeSecurityReport_LongDescription, ReporterTest
//@brief    Positive test for ComposeSecurityReport
//@input    Caller, Execution, FileType, Path, Description
***************************************************************************************************
*/
TEST ( ReporterTest, vdapi_ComposeSecurityReport_LongDescription )
{
    ReporterInfo Info;
    SfTaskMessageReceiver* pInst = SfTaskMessageReceiver::GetInstance();
    std::string AbnormalDesc = "A";
    for(int i = 0; i < 1500; i++) AbnormalDesc+="A";

    if (pInst)
    {
        EXPECT_FALSE( SF_FAILED(
    	pInst->composeSecurityReport( Caller, 
									  FileType, 
									  Path, 
									  AbnormalDesc.c_str(), 
									  Name, 
									  &Info)
    	));
    }
}

/**
***************************************************************************************************
//@sut      vdapi_ComposeSecurityReport_n, ReporterTest
//@brief    Nagative test for ComposeSecurityReport
//@input    Caller, Execution, FileType, Path, Description
***************************************************************************************************
*/
TEST ( ReporterTest, vdapi_ComposeSecurityReport_n )
{
    ReporterInfo Info;
    SfTaskMessageReceiver* pInst = SfTaskMessageReceiver::GetInstance();
    if (pInst)
    {
        EXPECT_FALSE( SF_FAILED(
    	pInst->composeSecurityReport( Caller, 
									  FileType, 
									  "ABSC", 
									  Description, 
									  Name, 
									  &Info)
    	));
    }
}

/***************************************************************************************************
//@sut      SendLogTest, ReporterTest
//@brief    Positive Test 1 for SendLogTest
//@input    Caller, Execution, FileType, Path, Description
***************************************************************************************************
*/
TEST (ReporterTest, SendLogTest)
{
    ReporterAPI api;
    std::string testfile = "/opt/test";
    std::string command = "echo ";
    command += api.GetFormattedTime();
    command += " > ";
    command += testfile;

    int ret = std::system(command.c_str());
    SF_LOG_I("[TEST] Command : %s(%d)",command.c_str(), ret);

    ReporterInfo Info;
    SfTaskMessageReceiver* pInst = SfTaskMessageReceiver::GetInstance();
    if (pInst)
    {
        EXPECT_TRUE( SF_SUCCESS(
    	pInst->composeSecurityReport( Caller, 
    								  FileType, 
    								  testfile.c_str(), 
    								  Description, 
    								  Name, 
    								  &Info)
    	));
    }

    SfRecorder reportHandler;
    SF_STATUS r = reportHandler.SendLogToSCS(&Info);
    EXPECT_TRUE(SF_SUCCESS(r));

    command = "rm ";
    command += testfile;
    ret = std::system(command.c_str());
    SF_LOG_I("[TEST] Command : %s(%d)",command.c_str(), ret);
}

/***************************************************************************************************
//@sut      SendSelfLogTest, ReporterTest
//@brief    Positive Test 2 for SendLogTest
//@input    Caller, Execution, FileType, Path, Description
***************************************************************************************************
*/
TEST (ReporterTest, SendSelfLogTest)
{
    SelfReport selfReport;
    selfReport.reportData["caller"] = "UNIT_TC";
    selfReport.reportData["PID"] = "0";
    selfReport.reportData["process"] = "TC";
    selfReport.reportData["signal"] = "0";
    selfReport.description = "fspmd unit test";
    SfRecorder reportHandler;
    SF_STATUS r = reportHandler.SendLogToSCS(&selfReport);
    EXPECT_TRUE(SF_SUCCESS(r));
}

/***************************************************************************************************
//@sut      SendSecurityReport_Normal_LOG, ReporterTest
//@brief    Positive Test 1 for SendLogTest
//@input    Caller, Execution, FileType, Path, Description
***************************************************************************************************
*/
TEST( ReporterTest, SendSecurityReport_Normal_LOG)
{
    ReporterAPI api;
    int r = api.SendSecurityReport(Caller, FileType, Path, Description, 0);
    EXPECT_TRUE( r == (int)SF_STATUS_OK );
}

/***************************************************************************************************
//@sut      SendSecurityReport_LongDescription_LOG, ReporterTest
//@brief    Positive Test 1 for SendLogTest
//@input    Caller, Execution, FileType, Path, Description
***************************************************************************************************
*/
TEST( ReporterTest, SendSecurityReport_LongDescription_LOG)
{
    std::string dummyDescription = "A";
    for(int i = 0; i < 1500 ;i++) dummyDescription += "A";
    ReporterAPI api;
    int r = api.SendSecurityReport(Caller, FileType, Path, dummyDescription.c_str(), 0);
    EXPECT_TRUE( r == (int)SF_STATUS_OK );


    SfFilesList subDir;
    SfFilesList datafiles;
    datafiles.clear();
    subDir.clear();
    
    const std::string reportDumyBaseDir = tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/data/report/");

    if( !ListFolderContent(reportDumyBaseDir,datafiles,subDir)){
        SF_LOG_E("[TEST] Fail to list up files in directory ;");
    }
    EXPECT_EQ(datafiles.size(), 0);
}

/***************************************************************************************************
//@sut      vdapi_ReporterInstance_p, ReporterTest
//@brief    Positive Test 1 for vdapi_ReporterInstance_p
//@input    None
***************************************************************************************************
*/
TEST( ReporterTest, vdapi_ReporterInstance_p)
{
    SfTaskMessageReceiver* pInst = NULL;
    pInst = SfTaskMessageReceiver::GetInstance();

    if (pInst)
    {
        SfTaskMessageReceiver::ReleaseInstance();
        EXPECT_TRUE ( 1 );
    }
}
