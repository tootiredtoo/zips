/**
****************************************************************************************************
* @file SfRecorder.cpp
* @brief Security framework [SF] Handle Report from Other Security Components
* @author Namgwon Lee (namgwon.lee@samsung.com)
* @date Created JULY 20, 2017 09:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2017. All rights reserved.
****************************************************************************************************
*/
#include "SfRecorder.h"
#include "libprovider/SfSettings.h"
#include "libprotocol/SfEnvironmentFormat.h"
#include "libprimitive/SfStringUtils.h"
#include "libprimitive/UnixSocket.h"
#include "common/SfTasksTags.h"
#include "net_connection.h"

//for UI
#include <app.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <unistd.h>
#include <vconf.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <libintl.h> // i18n gettext()
#include <jsoncpp/json/json.h>
#include <limits.h>

#define CALLER_LIMIT 16
#define TYPE_LIMIT 16
#define PATH_LIMIT 256
#define SHA256_HASH_LIMIT 64
#define DESC_LIMIT 1024

#define CALC_HASH_FILE_SIZE_LIMIT 30000000

static const char* basepath = "/opt/GAIA/logs/";

extern "C" char *sf_get_text(const char *message)
{
    return gettext(message);
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfRecorder::networkErrorPopupShow()
{
    SF_LOG_I("called;");
    app_control_h app_control = 0;
    app_control_create(&app_control);
    if ( NULL == app_control )
    {
        SF_LOG_E("bundle_create() failed;");
        return;
    }
    
    app_control_set_operation(app_control, APP_CONTROL_OPERATION_DEFAULT);
    app_control_add_extra_data(app_control, "wnd", BundleWin[SF_WINDOW_TYPE_MSGBOX].Type);
    app_control_add_extra_data(app_control, "id", BundleWin[SF_WINDOW_TYPE_MSGBOX].Id);

    Json::Value root;
    root["type"]         = 0; // MSG_BOX_TITLE_OK
    root["title"]        = _("COM_SID_ERROR_KR_ERROR");
    root["message"]      = _("TV_SID_NETWORK_ERROR_OCCURRED_TRY_AGAIN");

    Json::FastWriter fastWriter;
    std::string messageJson = fastWriter.write(root);
    app_control_add_extra_data(app_control, "value", messageJson.c_str());
    
    app_control_set_app_id(app_control, SF_SMART_SECURITY_PACKAGE_NAME);
    if(app_control_send_launch_request(app_control, NULL, NULL) != APP_CONTROL_ERROR_NONE)
    {
        SF_LOG_E("app launch error!");
    }
    
    app_control_destroy(app_control);
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRecorder::SendLogToSCS(ReporterInfo* pInfo) const
{
    SF_LOG_I("Called;");
    if (pInfo == NULL) {
        SF_LOG_E("pInfo is NULL;");
        return SF_STATUS_FAIL;
    }

    // SfSleepMs(c_second *5 );
    return sendReport(pInfo);
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRecorder::SendLogToSCS(SelfReport* sInfo) const
{
    SF_LOG_I("Called;");
    if (sInfo == NULL) {
        SF_LOG_E("sInfo is NULL;");
        return SF_STATUS_FAIL;
    }

    return sendReport(sInfo);
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfRecorder::checkNetworkStatus() const
{
    SF_LOG_E("++");
    SF_STATUS ret = SF_STATUS_FAIL;

    connection_h netState = NULL;
    if (connection_create(&netState) != CONNECTION_ERROR_NONE) {
        SF_LOG_E("connection_create() Fail;");
        return ret;
    }

    connection_wifi_state_e wifiState = CONNECTION_WIFI_STATE_DEACTIVATED;
    if (connection_get_wifi_state(netState, &wifiState) == CONNECTION_ERROR_NONE) {
        if (wifiState == CONNECTION_WIFI_STATE_CONNECTED) {
            SF_LOG_I("wifi is connected;");
            ret = SF_STATUS_OK;
        }
    }

    connection_ethernet_state_e ethState = CONNECTION_ETHERNET_STATE_DEACTIVATED;
    if (connection_get_ethernet_state(netState, &ethState) == CONNECTION_ERROR_NONE) {
        if (ethState == CONNECTION_ETHERNET_STATE_CONNECTED) {
            SF_LOG_I("ethernet is connected;");
            ret = SF_STATUS_OK;
        }
    }

    if (netState != NULL) {
        connection_destroy(netState);
    }

    SF_LOG_E("--");
    return ret;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string SfRecorder::GetFormattedTime( const char* format )
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

    if ( 0 == strftime( formattedTime, sizeof( formattedTime ), format, &newTime ) )
    {
        SF_LOG_E( "strftime() failed;" );
        return std::string();
    }

    return formattedTime;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
int SfRecorder::GetScsServerConfig() const
{
    const char* relImage   = "/etc/release";
    if( FileExists(relImage) )
    {
        return SF_SCS_MODULE_ID_REL;
    }
    else
    {
        SF_LOG_I("Get Debug Image");
    	return SF_SCS_MODULE_ID_DBG;
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
#ifdef LICENSING_PRODUCT
SF_STATUS SfRecorder::GetScsHash( ReporterInfo* pInfo ) const
{
    SF_LOG_I("this function is not supported in LICENSING image;");
    return SF_STATUS_OK;
}
#else
SF_STATUS SfRecorder::GetScsHash( ReporterInfo* pInfo ) const
{
    SF_STATUS r = SF_STATUS_OK;
    size_t limit = 0xFFFFFFFF;
    std::string message;
    std::string hash;
    std::vector<uint8_t> content;
    struct stat fileStatus;

    if (!FileExists(pInfo->ExtInfo.fileName))
    {
        SF_LOG_E("[%s] File is not exist;", pInfo->ExtInfo.fileName );
        pInfo->ExtInfo.fileHash = NULL;
        pInfo->ExtInfo.fileHashLength = 0;
        return SF_STATUS_OK;
    }

    long fileSize = GetFileSizeFromPath(pInfo->ExtInfo.fileName);
    if (fileSize >= CALC_HASH_FILE_SIZE_LIMIT)
    {
        SF_LOG_E("[%s] File is too big(%ld)", pInfo->ExtInfo.fileName, fileSize);
        return SF_STATUS_FAIL;
    }

    if (IsProcFs(pInfo->ExtInfo.fileName))
    {
        if (readProcFsFile(pInfo->ExtInfo.fileName, message, limit))
        {
            r = scs::calcHashHex(message, hash) ? r : SF_STATUS_FAIL;
        }
    }
    else
    {
        if( readRegularFile( pInfo->ExtInfo.fileName, fileStatus, content, limit, pInfo->SendFileFlag ) )
        {
            r = scs::calcHashHex(content, hash) ? r : SF_STATUS_FAIL;
        }
    }

    if (SF_SUCCESS(r))
    {
        pInfo->ExtInfo.fileHash = strndup(hash.c_str(), hash.length());
        pInfo->ExtInfo.fileHashLength = hash.length();
    }

    return r;
}
#endif

/**
****************************************************************************************************
*
****************************************************************************************************
*/
#ifdef LICENSING_PRODUCT
SF_STATUS SfRecorder::sendReport(ReporterInfo* pInfo) const
{
    SF_LOG_I("this function is not supported in LICENSING image;");
    return SF_STATUS_OK;
}

SF_STATUS SfRecorder::sendReport(SelfReport* sInfo) const
{
    SF_LOG_I("this function is not supported in LICENSING image;");
    return SF_STATUS_OK;
}
#else
SF_STATUS SfRecorder::sendReport(ReporterInfo* pInfo) const
{
    if (pInfo == NULL) {
        SF_LOG_E("ReportInfo is NULL;");
        return SF_STATUS_FAIL;
    }

    if (SF_FAILED(checkNetworkStatus())) {
        SF_LOG_E("there is a network problem");
        return SF_STATUS_FAIL;
    }

    scs::ExtReport extInfo;
    
    if (pInfo->ExtInfo.caller) {
        size_t len = strnlen(pInfo->ExtInfo.caller, CALLER_LIMIT);
        extInfo.caller = strndup(pInfo->ExtInfo.caller, len);
        extInfo.callerLength = len;
    }
    
    if (pInfo->ExtInfo.fileType) {
        size_t len = strnlen(pInfo->ExtInfo.fileType, TYPE_LIMIT);
        extInfo.fileType = strndup(pInfo->ExtInfo.fileType, len);
        extInfo.fileTypeLength = len;
    }
    
    if (pInfo->ExtInfo.fileName) {
        size_t len = strnlen(pInfo->ExtInfo.fileName, PATH_LIMIT);
        extInfo.fileName = strndup(pInfo->ExtInfo.fileName, len);
        extInfo.fileNameLength = len;
    }
    
    if (pInfo->ExtInfo.fileHash) {
        size_t len = strnlen(pInfo->ExtInfo.fileHash, SHA256_HASH_LIMIT);
        extInfo.fileHash = strndup(pInfo->ExtInfo.fileHash, len);
        extInfo.fileHashLength = len;
    }
    
    if (pInfo->ExtInfo.description) {
        size_t len = strnlen(pInfo->ExtInfo.description, DESC_LIMIT);
        extInfo.description = strndup(pInfo->ExtInfo.description, len);
        extInfo.descriptionLength = len;
    }

#ifdef DEBUG_REPORT
    SF_LOG_I("Report: ");
    SF_LOG_I("	Caller: %s", pInfo->ExtInfo.caller);
    SF_LOG_I("	Description: %s", pInfo->ExtInfo.description);    
#endif
    int ret = scs::sendExtReport(GetScsServerConfig(), extInfo);
    SF_LOG_I("sendExtReport done[%d] : %s", ret, ((pInfo->ExtInfo.fileName != NULL) ? pInfo->ExtInfo.fileName : ""));
    return SF_STATUS_OK;
}

SF_STATUS SfRecorder::sendReport(SelfReport* sInfo) const
{
    int moduleId = GetScsServerConfig();
    if (moduleId == SF_SCS_MODULE_ID_REL)
    {
        SF_LOG_W("Self report disabled for REL img");
        return SF_STATUS_OK;
    }
    Json::Value root(Json::objectValue);
    for (const auto& [key, value] : sInfo->reportData) {
        root[key] = value;
    }
    root["description"] = sInfo->description;
    Json::StreamWriterBuilder writer;
    std::string report = Json::writeString(writer, root);
    SF_LOG_E("report: %s", report.c_str());
    int ret = scs::sendReport(SF_SCS_SELF_MODULE_ID, REPORT_TYPE, report);
    SF_LOG_I("sendReport done[%d]", ret);
    return SF_STATUS_OK;
}
#endif

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SecurityReport::ReportTaskWorker::ReportTaskWorker() : ISfThread( "ReportTaskWorker" )
{
}

SecurityReport::ReportTaskWorker::~ReportTaskWorker()
{
    ISfThread::Stop();
    ISfThread::Join();
}

//----------------------------------------------------------------------------------------------------------------
SF_STATUS SecurityReport::ReportTaskWorker::Execute(const REPORT_CODE operation)
{
    SF_LOG_I("Call;");
    ISfThread::Join();
    HandleOperation(operation);
    return ISfThread::Run();
}

//----------------------------------------------------------------------------------------------------------------
Uint64 SecurityReport::ReportTaskWorker::CovertByteToKB(Uint64 byte)
{
    return byte / 1024;
}

//----------------------------------------------------------------------------------------------------------------
void SecurityReport::ReportTaskWorker::ThreadFunction()
{
    switch (opcode)
    {
    case (int)CLEAR: {
        const char *dataPath = tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/data/report/");
        if (ClearDirectory(dataPath) != 0) {
            SF_LOG_W("Fail to clearReportDataFiles");
        } }
        break;
    case (int)SHARED_CLEAR: {
        const char *sharedPath = tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/shared/");
        if (ClearDirectory(sharedPath) != 0) {
            SF_LOG_W("Fail to clearSharedFiles");
        } }
        break;
    case (int)CCLOG_CLEAR: {
        if (ClearDirectory(basepath) != 0) {
            SF_LOG_W("Fail to clearCCLogFiles");
        } }
        break;
    case (int)GET_RW_SIZE: {
        const std::string sf_rw_path = tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/");
        Uint64 totalDataSize = GetDirectoryFlashUsage(sf_rw_path);
        if (CovertByteToKB(totalDataSize) > 500) {
            dlog_print(DLOG_ERROR, "[securityreport]", "data path size is bigger than 500KB( %" PRIu64 ")", totalDataSize);
        } }
        break;
    case (int)GET_CC_SIZE: {
        const std::string sf_cclog_path = "/opt/GAIA/logs/";
        Uint64 totalCCLogSize = GetDirectoryFlashUsage(sf_cclog_path);
        if (CovertByteToKB(totalCCLogSize) > 500) {
            dlog_print(DLOG_ERROR, "[securityreport]", "cclog path size is bigger than 500KB( %" PRIu64 ")", totalCCLogSize);
        } }
        break;
    default:
        break;
    }
}

//----------------------------------------------------------------------------------------------------------------
void SecurityReport::ReportTaskWorker::HandleOperation(const REPORT_CODE operation)
{
    opcode = (int)operation;
}
