/*
SfTaskMessageReceiver.cpp
*/
#include "SfTaskMessageReceiver.h"
#include "SfKUEPSwitcher.h"

#include "common/SfJSONTags.h"
#include "common/SfTasksTags.h"
#include "libprimitive/SfSharedFile.h"
#include "libprimitive/SfStringUtils.h"
#include <arpa/inet.h>
#include <sys/time.h>
#include <fstream>

//for UI
#ifdef SHOW_SMARTSECURITY_POPUP
#include <app.h>
#include <bundle.h>
#include <bundle_internal.h>
#endif 
#include <tzplatform_config.h>
#include <vconf.h>

#define SET_CURRENT_LOCALE_TEXT \
    char *lang_set = vconf_get_str(VCONFKEY_LANGSET); \
    setlocale(LC_ALL,lang_set); \
    if( lang_set && lang_set[0]) { free( lang_set ); } 
    
#define CALLER_LIMIT 16
#define TYPE_LIMIT 16
#define PATH_LIMIT 256

#define DISABLE   1
#define ENABLE    0

Bool gsf_usb_device_off = FALSE;
Bool gsf_power_off = FALSE;

SfTaskMessageReceiver* SfTaskMessageReceiver::m_pInstance = NULL;

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfTaskMessageReceiver* SfTaskMessageReceiver::GetInstance()
{
    if (m_pInstance == NULL)
    {
        m_pInstance = SF_NEW SfTaskMessageReceiver;
    }
    return m_pInstance;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfTaskMessageReceiver::ReleaseInstance()
{
    if (m_pInstance)
    {
        SF_DELETE m_pInstance;
        m_pInstance = NULL;
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::addReportQueue(const std::string& message)
{
    SF_LOG_I("[user block][%s];", message.c_str());

    ReporterInfo *pInfo = SF_NEW ReporterInfo;
    if (pInfo == NULL) {
        SF_LOG_E("pInfo is NULL;");
        return SF_STATUS_FAIL;
    }

    memset(pInfo->ReportSeq, 0x00, 20);
    memset(pInfo->FileName, 0x00, MAX_LEN);
    if (SF_FAILED(composeUserReporter(message, pInfo))) {
        SF_LOG_E("composing user notification fail;");
        freeReporterInfo(pInfo);
        return SF_STATUS_FAIL;
    }

    m_msgQueue.Push(pInfo);
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::composeSecurityReport(const char* strCaller, const char* strFileType,
                                                       const char* strPath, const char* strDescription,
                                                       const char* strFileName, ReporterInfo* pReporterInfo) const
{
    if (!pReporterInfo || !strCaller || !strFileType || !strPath || !strDescription || !strFileName) {
        SF_LOG_E("[Invalid param];");
        return SF_STATUS_FAIL;
    }

    size_t len = strnlen(strCaller, CALLER_LIMIT);
    pReporterInfo->ExtInfo.caller = strndup(strCaller, len);
    pReporterInfo->ExtInfo.callerLength = len;

    len = strnlen(strPath, PATH_LIMIT);
    pReporterInfo->ExtInfo.fileName = strndup(strPath, len);
    pReporterInfo->ExtInfo.fileNameLength = len;
    
    len = strnlen(strFileType, TYPE_LIMIT);
    pReporterInfo->ExtInfo.fileType = strndup(strFileType, len);
    pReporterInfo->ExtInfo.fileTypeLength = len;

    len = strnlen(strFileName, MAX_LEN - 1);
    memcpy(pReporterInfo->FileName, strFileName, len + 1); 
    pReporterInfo->FileName[sizeof(pReporterInfo->FileName) - 1] = '\0';

    std::string Description = "";
    std::string DescriptionContent = strDescription;

    if (!pReporterInfo->backupData) {
        std::map< std::string, SF_ENVIRONMENT_TYPE > ReportType;
        ReportType[EnvPro] = SF_ENVIRONMENT_TYPE_PROCESS;
        ReportType[EnvFile] = SF_ENVIRONMENT_TYPE_FILE;
        ReportType[EnvNet] = SF_ENVIRONMENT_TYPE_NETWORK;
        ReportType[EnvMmap] = SF_ENVIRONMENT_TYPE_MMAP;
        ReportType[EnvSnd] = SF_ENVIRONMENT_TYPE_SND_RCV;
        ReportType[EnvScript] = SF_ENVIRONMENT_TYPE_SCRIPT;
        ReportType[EnvReport] = SF_ENVIRONMENT_TYPE_REPORT;
        pReporterInfo->EnvironmentsType = ReportType[strFileType];

        SfStringUtils::SfStringVector items;
        SfStringUtils::SplitString(strDescription, items, ','); // first delimiter : comma(,)

        Int8 version = 0;
        for (SfStringUtils::SfStringVector::iterator it = items.begin(); it != items.end(); ++it)
        {
            std::string strversion = *it;
            if( strversion.find("ver") != std::string::npos)
            {
                SfStringUtils::SfStringVector itemsValue;
                SfStringUtils::SplitString(strversion, itemsValue, ':'); // second delimiter : colon (:)
                const char* value = itemsValue[1].c_str();
                version = (Int8)(value[1] - '0');
                break;
            }
        }
    
        Description = "[";
        Description += std::to_string(pReporterInfo->SendFileFlag);
        Description +="|";
        Description += pReporterInfo->ReportSeq;
        Description +="|";
        Description += std::to_string(version);
        Description +="]";
        Description += DescriptionContent.length() > 1024 ? DescriptionContent.substr(0, 1024) : DescriptionContent;
        SF_LOG_I("Desc : %s",Description.c_str());
    }
    else {
        Description += DescriptionContent.length() > 1024 ? DescriptionContent.substr(0, 1024) : DescriptionContent;
    }

    len = Description.length();
    pReporterInfo->ExtInfo.description = strndup(Description.c_str(), len);
    pReporterInfo->ExtInfo.descriptionLength = len;
    if (SF_SUCCESS(m_recorder.GetScsHash(pReporterInfo))) {
        SF_LOG_I("FileHash:[%s][%s];", pReporterInfo->ExtInfo.fileName, ((pReporterInfo->ExtInfo.fileHash != NULL) ? pReporterInfo->ExtInfo.fileHash : ""));
    }
    SF_LOG_I("Description : %s", pReporterInfo->ExtInfo.description);
    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
#ifdef SHOW_SMARTSECURITY_POPUP
void SfTaskMessageReceiver::kernelMessageDetailedShow()
{
    SF_LOG_I("called %s();",__FUNCTION__);

    app_control_h app_control = NULL;
    app_control_create(&app_control);
    if ( NULL == app_control )
    {
        SF_LOG_E("app_control_create failed;");
        return;
    }
    //for Blocked Window
    app_control_set_operation(app_control, APP_CONTROL_OPERATION_DEFAULT);
    app_control_add_extra_data(app_control, "wnd", BundleWin[SF_WINDOW_TYPE_BLOCKED_LIST_NOTI].Type);
    app_control_add_extra_data(app_control, "id", BundleWin[SF_WINDOW_TYPE_BLOCKED_LIST_NOTI].Id);
    
    app_control_set_app_id(app_control, SF_SMART_SECURITY_PACKAGE_NAME);
    if(app_control_send_launch_request(app_control, NULL, NULL) != APP_CONTROL_ERROR_NONE)
        SF_LOG_E("app launch fail!");

    app_control_destroy(app_control);
}
#endif 
/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfTaskMessageReceiver::SfTaskMessageReceiver()
    : m_userMsgSock()
    , m_kernelMsgSock()
    , m_msgQueue()
    , m_recorder()
    , m_userMsgThread("SfUserMsgThread")
    , m_kernelMsgThread("SfKernelMsgThread")
    , m_queueHandleThread("SfQueueThread")
    , m_inotifyMsgThread("SfInotify")
    , m_fsMonitor()
{
    launchThreads();
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfTaskMessageReceiver::~SfTaskMessageReceiver()
{
    terminateThreads();
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
int SfTaskMessageReceiver::launchThreads()
{
    SF_LOG_I("called;");

    if (!m_userMsgThread.IsRunning()) {
        m_userMsgThread.Start(SfTaskMessageReceiver::receiveUserMessage, static_cast<void*>(this));
    }

    if (!m_kernelMsgThread.IsRunning()) {
        m_kernelMsgThread.Start(SfTaskMessageReceiver::receiveKernelMessage, static_cast<void*>(this));
    }

    if (!m_queueHandleThread.IsRunning()) {
        m_queueHandleThread.Start(SfTaskMessageReceiver::threadQueueHandler, static_cast<void*>(this));
    }

    if (!m_inotifyMsgThread.IsRunning()) {
        m_inotifyMsgThread.Start(SfTaskMessageReceiver::threadInotifyHandler, static_cast<void*>(this));
    }

    return 0;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
int SfTaskMessageReceiver::terminateThreads()
{
    SF_LOG_I("called;");

    m_inotifyMsgThread.Stop();
    m_inotifyMsgThread.Join();
    
    m_userMsgThread.Stop();
    m_userMsgThread.Join();
    
    m_kernelMsgThread.Stop();
    m_kernelMsgThread.Join();
    
    m_queueHandleThread.Stop();
    m_msgQueue.ExitWaitPop();
    m_queueHandleThread.Join();

    return 0;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfTaskMessageReceiver::shouldThrowNotification( Int32 sysCallResult, SF_STATUS& result ) const //, const char* subject, const char* object, std::string& description ) const
{
    Bool r = FALSE;

    switch (static_cast< SF_STATUS >( sysCallResult ) )
    {
        case SF_STATUS_UEP_SIGNATURE_INCORRECT:
            result = SF_STATUS_UEP_SIGNATURE_INCORRECT;
            r = TRUE;
            break;
        case SF_STATUS_UEP_FILE_NOT_SIGNED:
            result = SF_STATUS_UEP_FILE_NOT_SIGNED;
            r = TRUE;
            break;
        case SF_STATUS_RESOURCE_BLOCK:
            result = SF_STATUS_RESOURCE_BLOCK;
            r = TRUE;
            break;
        case SF_STATUS_SYSTEM_ERROR_IN_READ:
            result = SF_STATUS_SYSTEM_ERROR_IN_READ;
            r = TRUE;
            break;
        case SF_STATUS_NOT_ENOUGH_BUFFER:
            result = SF_STATUS_NOT_ENOUGH_BUFFER;
            r = TRUE;
            break;
        default:
            break;
    }
    
    return r;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::ParseTextByDelimiter(const char* pszFullText, const char *pDelimiter, char** ppszFront, char** ppszRear)
{
    if ( (pszFullText == NULL) || (pDelimiter == NULL) || (ppszFront == NULL) || (ppszRear == NULL) )
    {
        SF_LOG_E("[Invalid Arguments];");
        return SF_STATUS_FAIL;
    }

    int nDeliSize = strlen(pDelimiter);
    if (nDeliSize < 1)
    {
        SF_LOG_E("[Invalid Argument];");
        return SF_STATUS_FAIL;
    }

    const char *pFound = strstr(pszFullText, pDelimiter);
    if (pFound == NULL)
    {
        SF_LOG_I("[Not Found]");
        return SF_STATUS_FAIL;
    }
    int nTotalLen = strlen(pszFullText);
    int nFrontLen = (int)(pFound - pszFullText);   
    int nRearLen = nTotalLen - nFrontLen - nDeliSize;
    SF_LOG_I("[size : %d, %d, %d, %d]", nDeliSize, nTotalLen, nFrontLen, nRearLen);
    
    if ( (nFrontLen > 0) && (nRearLen > 0) )
    {
        *ppszFront = (char*)malloc(nFrontLen + 1);
        *ppszRear = (char*)malloc(nRearLen + 1);
        if (*ppszFront && *ppszRear)
        {
            sf_memcpy(*ppszFront, pszFullText, nFrontLen);
            (*ppszFront)[nFrontLen] = 0x00;
            sf_memcpy(*ppszRear, pszFullText + nFrontLen + nDeliSize, nRearLen);
            (*ppszRear)[nRearLen] = 0x00;
            return SF_STATUS_OK;
        }
        else
        {
            SF_LOG_E("[Failed to allocating memory];");
            sf_free(*ppszFront);
            sf_free(*ppszRear);
        }
    }
    return SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::composeKernelReporter( const SfPacket* pPacket, ReporterInfo* pReportInfo ) 
{
    SF_STATUS ret = SF_STATUS_FAIL;
    int Type = 0;
    std::string Caller;
    std::string Path;
    std::string Description;
    std::string BlockedTarget;
    std::string FileType;
    SF_STATUS SFDResult;

    if ( (pPacket == NULL) || (pReportInfo == NULL) )
    {
        SF_LOG_E("Invalid param;");
        return ret;
    }

    if ( (SF_PACKET_TYPE_OPERATION != pPacket->header.type) && (SF_PACKET_TYPE_REPORT != pPacket->header.type) )
    {
        SF_LOG_E( "Wrong packet type [%d];", pPacket->header.type );
        return ret;
    }

    if ( pPacket->env )
    {
        switch ( Type = pPacket->env->type )
        {
            case SF_ENVIRONMENT_TYPE_NETWORK:
            {
                const SfNetworkEnvironment* pNetEnv = (const SfNetworkEnvironment*)pPacket->env;
                if( shouldThrowNotification( pNetEnv->processContext.sysCallResult, SFDResult) )
                {
                    std::string srcAddr, destAddr;

                    struct in_addr ip_addr;
                    ip_addr.s_addr = pNetEnv->addr;
                    srcAddr = pNetEnv->processContext.pProcessName;
                    destAddr = std::string( inet_ntoa( ip_addr ) );
                    Path = srcAddr; Path += " -> " + destAddr;

                    Caller        = "Firewall";
                    FileType      = s_EnvironmentInfo[ Type ].Format;
                    BlockedTarget = destAddr;
                    Description   = composeDescription( srcAddr.c_str(),
                                                        destAddr.c_str(), 
                                                        NULL, 
                                                        SFDResult );
                    ret         = SF_STATUS_OK;
                }
            }break;

            case SF_ENVIRONMENT_TYPE_SND_RCV:
            {
                SF_LOG_I("SF_ENVIRONMENT_TYPE_SND_RCV");
                
                const SfSndRcvEnvironment* pSndRcvEnv = (const SfSndRcvEnvironment*)pPacket->env;
                std::string srcAddr, destAddr;

                struct in_addr ip_addr;
                ip_addr.s_addr = pSndRcvEnv->srcAddr;
                srcAddr = inet_ntoa(ip_addr) + std::string(":");
                srcAddr.append(SfStringUtils::NumberToString(ntohs(pSndRcvEnv->srcPort)));

                ip_addr.s_addr = pSndRcvEnv->destAddr;
                destAddr = inet_ntoa(ip_addr) + std::string(":");
                destAddr.append(SfStringUtils::NumberToString(ntohs(pSndRcvEnv->destPort)));
                Path = srcAddr; Path += "->" + destAddr;

                Caller        = "Firewall";
                FileType      = s_EnvironmentInfo[ Type ].Format;
                BlockedTarget = destAddr;
                Description   = composeDescription( srcAddr.c_str(),
                                                    destAddr.c_str(),
                                                    NULL, 
                                                    SF_STATUS_RESOURCE_BLOCK );
                ret           = SF_STATUS_OK;
            }break;

            case SF_ENVIRONMENT_TYPE_FILE:
            {
                const SfFileEnvironment* pFileEnv = (const SfFileEnvironment*)pPacket->env;
                if( shouldThrowNotification( pFileEnv->processContext.sysCallResult, SFDResult ) )
                {
                    Caller        = "kUEP";
                    Path          = pFileEnv->pFileName;
                    BlockedTarget = FindFileNameFromPath( pFileEnv->pFileName );
                    FileType      = s_EnvironmentInfo[ Type ].Format;
                    Description   = composeDescription( BlockedTarget.c_str(),
                                                        FileType.c_str(),
                                                        NULL, 
                                                        SFDResult );
                    ret           = SF_STATUS_OK;
                }
            }break;

            case SF_ENVIRONMENT_TYPE_PROCESS:
            {
                char *pszFrontText = NULL;
                char *pszRearText = NULL;
                
                SfProcessEnvironment* pProcEnv = (SfProcessEnvironment*)pPacket->env;
                if (shouldThrowNotification( pProcEnv->processContext.sysCallResult, SFDResult) )
                {
                    if ((pProcEnv->processContext.sysCallResult == SF_STATUS_SYSTEM_ERROR_IN_READ) ||
                         (pProcEnv->processContext.sysCallResult == SF_STATUS_NOT_ENOUGH_BUFFER))
                    {
                        pReportInfo->SysError = 1;
                    }
                    if (strstr(pProcEnv->pProcessName, SF_MNT_INFO_SEP))
                    {
                        if (ParseTextByDelimiter((const char*)(pProcEnv->pProcessName), 
                                                  (const char*)SF_MNT_INFO_SEP, 
                                                  &pszFrontText, 
                                                  &pszRearText) == SF_STATUS_OK)
                        {
                            if (pszFrontText && pszRearText)
                            {
                                sf_free(pProcEnv->pProcessName);
                                pProcEnv->pProcessName = pszFrontText;
                            }
                            else
                            {
                                sf_free(pszFrontText);
                                sf_free(pszRearText);
                            }
                        }
                    }
                    Caller        = "kUEP";
                    Path          = pProcEnv->pProcessName;
                    BlockedTarget = FindFileNameFromPath( pProcEnv->pProcessName );
                    FileType      = s_EnvironmentInfo[ Type ].Format;
                    Description   = composeDescription( BlockedTarget.c_str(),
                                                        FileType.c_str(),
                                                        pszRearText, 
                                                        SFDResult );
                    sf_free(pszRearText);
                    ret           = SF_STATUS_OK;
                }
            }break;

            case SF_ENVIRONMENT_TYPE_MMAP:
            {   
                SfMmapEnvironment* pMMAPEnv = (SfMmapEnvironment*)pPacket->env;
                if( shouldThrowNotification( pMMAPEnv->processContext.sysCallResult,SFDResult) )
                {
                    char *pszFrontText = NULL;
                    char *pszRearText = NULL;

                    if ((pMMAPEnv->processContext.sysCallResult == SF_STATUS_SYSTEM_ERROR_IN_READ) ||
                         (pMMAPEnv->processContext.sysCallResult == SF_STATUS_NOT_ENOUGH_BUFFER))
                    {
                        pReportInfo->SysError = 1;
                    }

                    if (strstr(pMMAPEnv->pLibraryName, SF_MNT_INFO_SEP))
                    {
                        if (ParseTextByDelimiter((const char*)(pMMAPEnv->pLibraryName), 
                                                  (const char*)SF_MNT_INFO_SEP, 
                                                  &pszFrontText, 
                                                  &pszRearText) == SF_STATUS_OK)
                        {
                             if (pszFrontText && pszRearText)
                            {
                                sf_free(pMMAPEnv->pLibraryName);
                                pMMAPEnv->pLibraryName = pszFrontText;
                            }
                            else
                            {
                                sf_free(pszFrontText);
                                sf_free(pszRearText);
                            }
                        }
                    }
                    Caller        = "kUEP";
                    Path          = pMMAPEnv->pLibraryName;
                    BlockedTarget = FindFileNameFromPath(pMMAPEnv->pLibraryName );
                    FileType      = s_EnvironmentInfo[ Type ].Format;
                    Description   = composeDescription( BlockedTarget.c_str(),
                                                        FileType.c_str(),
                                                        pszRearText, 
                                                        SFDResult );
                    sf_free(pszRearText);
                    ret           = SF_STATUS_OK;
                }
            }break;

            default:
                SF_LOG_E( "Wrong environment type %d;", pPacket->env->type );
                break;
        }
        SfGetUsSysTimeAsString(pReportInfo->ReportSeq,sizeof(pReportInfo->ReportSeq));
    } /* end if (pPacket->env) */
    else if (pPacket->op)
    {
        ret = SF_STATUS_FAIL;
        
        switch (pPacket->op->type)
        {
            case SF_OPERATION_TYPE_REPORT_NET:     /* fall trrough */
            case SF_OPERATION_TYPE_REPORT_PROCESS: /* fall trrough */
            case SF_OPERATION_TYPE_REPORT_FILE:
                {
                    SF_LOG_I( "[operation type %d];", pPacket->op->type);
                    const SfOperationSecurityReport* pReportOp = (const SfOperationSecurityReport*)pPacket->op;

                    if( SF_FAILED( checkReportPacket(pReportOp)) )
                    {
                         break;
                    }

                    Caller                        = pReportOp->caller;
                    Path                          = pReportOp->filepath;
                    FileType                      = pReportOp->filetype;
                    BlockedTarget                 = FindFileNameFromPath( pReportOp->filepath );
                    pReportInfo->EnvironmentsType = SF_ENVIRONMENT_TYPE_REPORT;
                    pReportInfo->SendFileFlag     = pReportOp->sendfileflag;
                    Description                   = pReportOp->description;

                    if( strlen(pReportOp->desc_time) > 0)
                        sf_strncpy( pReportInfo->ReportSeq, pReportOp->desc_time, sizeof(pReportInfo->ReportSeq) );

                    SF_LOG_I( "[caller:%s, path:%s, filetype:%s, blocked target:%s, desc:%s, sendflag:%d];", 
                        Caller.c_str(), Path.c_str(), FileType.c_str(), BlockedTarget.c_str(), Description.c_str(), pReportOp->sendfileflag);
                    ret = SF_STATUS_OK;
                }
                break;
            default:
                SF_LOG_E( "[Wrong operation type %d];", pPacket->op->type);
                break;
        }
    } /* end if (pPacket->op) */
    
    if (ret == SF_STATUS_OK)
    {
        pReportInfo->EnvironmentsType = Type;
        ret = composeSecurityReport( Caller.c_str(), FileType.c_str(), Path.c_str(), Description.c_str(), BlockedTarget.c_str(), pReportInfo );
    }
    return ret;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::composeUserReporter( const std::string& message, ReporterInfo* pReportInfo ) const
{
    SF_STATUS ret = SF_STATUS_FAIL;
    
    if (pReportInfo == NULL) {
        return SF_STATUS_FAIL;
    }

    try {
        Json::Value root;
        Json::Reader reader;
        if (!reader.parse(message, root, false)) {
            SF_LOG_E("Parse(%s) failed;", message.c_str());
            return SF_STATUS_FAIL;
        }
        
        const char* Caller = root[ c_taskTagCaller ].asCString();
        const char* BlockedPath = root[ c_taskTagPath ].asCString();
        const char* szDescription = root[ c_taskTagDescription ].asCString();
        const char* FileType = root[ c_taskTagFileType ].asCString();
        pReportInfo->EnvironmentsType = SF_ENVIRONMENT_TYPE_REPORT;
        pReportInfo->SendFileFlag = root[ c_taskReportFileSend ].asInt();
        pReportInfo->backupData = root[ c_taskReportBackupData].asBool();
        sf_strncpy(pReportInfo->ReportSeq, root[ c_taskTagReportSeq ].asCString(), sizeof(pReportInfo->ReportSeq) );

        if (Caller && FileType && szDescription) {
            ret = composeSecurityReport( Caller, FileType, BlockedPath, szDescription, FindFileNameFromPath(BlockedPath).c_str(), pReportInfo );
        }
    }
    catch (Json::Exception& e) {
        SF_LOG_E("Exception from Json exception[%s];", e.what());
        return SF_STATUS_FAIL;
    }

    return ret;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string SfTaskMessageReceiver::composeDescription( const char* subject, const char* object, const char* pExtra, SF_STATUS result ) const
{
    std::map< SF_STATUS, std::string > action;
    action[ SF_STATUS_UEP_SIGNATURE_INCORRECT ] = "SF_STATUS_UEP_SIGNATURE_INCORRECT";
    action[ SF_STATUS_UEP_FILE_NOT_SIGNED ]     = "SF_STATUS_UEP_FILE_NOT_SIGNED";
    action[ SF_STATUS_RESOURCE_BLOCK ]          = "SF_STATUS_RESOURCE_BLOCK";

    std::string description = "ver:\""; description += "1\",";
    description += "subject:\""; description += subject; description += "\",";
    description += "object:\""; description += object; description += "\",";
    description += "result:\""; description += action[result].c_str(); 
    if (pExtra)
    {
        description += "("; description += pExtra; description += ")";
    }
    description += "\",";
    return description;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::freeReporterInfo( ReporterInfo* pReporterInfo )
{
    if (pReporterInfo)
    {
        sf_free(pReporterInfo->ExtInfo.caller);
        sf_free(pReporterInfo->ExtInfo.fileType);
        sf_free(pReporterInfo->ExtInfo.fileName);
        sf_free(pReporterInfo->ExtInfo.fileHash);
        sf_free(pReporterInfo->ExtInfo.description);
        SF_DELETE pReporterInfo;
    }
        
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::checkReportPacket(const SfOperationSecurityReport* pReportOp ) const
{
    if( pReportOp->caller == NULL || pReportOp->filepath == NULL || 
        pReportOp->filetype == NULL || pReportOp->description == NULL || pReportOp->desc_time == NULL)
    {
        //Todo: change LogLevel Info to Error after kernel released;
        //SF_LOG_I("[Caller:%s | path : %s | type : %s ]", pReportOp->caller, pReportOp->filepath, pReportOp->filetype);
        SF_LOG_I("failed;");
        return SF_STATUS_FAIL;
    }
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfTaskMessageReceiver::getTaskName( const std::string& msg, std::string& name )
{
    Json::Value root;
    Json::Reader reader;
    SF_STATUS ret = SF_STATUS_OK;

    if( !reader.parse( msg, root, false ) )
    {
        SF_LOG_E( "Parse(%s) failed;", msg.c_str() );
        return SF_STATUS_FAIL;
    }
        
    name = root[ c_taskTagTaskName ].asString();

    return ret;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void* SfTaskMessageReceiver::receiveKernelMessage(void* arg)
{
    SF_LOG_W("called;");
    
    if (arg == NULL) {
        SF_LOG_E("arg is NULL;");
        return NULL;
    }
    
    SfTaskMessageReceiver *pSelf = static_cast<SfTaskMessageReceiver*>(arg);
    if (pSelf != NULL) {
#ifdef USE_PLUGIN
	    pthread_setname_np(pthread_self(), "sfpmd");
#else	    
	    const char *threadName = pSelf->m_kernelMsgThread.GetThreadName().c_str();
	    pthread_setname_np(pthread_self(), threadName);
#endif	    
    }

    while (pSelf->m_kernelMsgThread.IsRunning()) {
        if (SF_SUCCESS(pSelf->m_kernelMsgSock.Connect())) {
            break;
        }
        else {
            SfSleepMs(c_second);
        }
    }

    if (SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_CONNECT))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_OPEN))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_EXEC))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_MMAP))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_SENDMSG))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_RECVMSG))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_REPORT_NET))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_REPORT_PROCESS))
         || SF_FAILED(pSelf->m_kernelMsgSock.JoinGroup(SF_OPERATION_TYPE_REPORT_FILE))) {
        SF_LOG_E( "JoinGroup() failed;" );
    }

    while (pSelf->m_kernelMsgThread.IsRunning()) {
        const Ulong c_timeOut = c_second * 1000;
        if (SF_FAILED(pSelf->m_kernelMsgSock.ReadyForRead(c_timeOut))) {
            continue;
        }

        SfPacket *pPacket = NULL;
        if (SF_FAILED(pSelf->m_kernelMsgSock.Receive(pPacket))) {
	    SF_LOG_E("kernel Receive  error;");
            SfDestroyPacket(pPacket);
            continue;
        }

        ReporterInfo *pInfo = SF_NEW ReporterInfo;
        if (pInfo == NULL) {
            SF_LOG_E("memory error;");
            SfDestroyPacket(pPacket);
            continue;
        }

        memset(pInfo->ReportSeq, 0x00, 20);
        memset(pInfo->FileName, 0x00, MAX_LEN);
        if (SF_SUCCESS(pSelf->composeKernelReporter(pPacket, pInfo))) {
            pSelf->m_msgQueue.Push(pInfo);
        }
        else {
            pSelf->freeReporterInfo(pInfo);
        }

        // Because of CPU Scheduling added sleep.
        SfSleepMs(1);
        SfDestroyPacket(pPacket);
    }
    return NULL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void *SfTaskMessageReceiver::receiveUserMessage(void *arg)
{
    SF_LOG_W("called;");
    if (arg == NULL) {
        return NULL;
    }

    SfTaskMessageReceiver *pSelf = static_cast<SfTaskMessageReceiver *>(arg);
    if (pSelf != NULL) {
        const char *threadName = pSelf->m_userMsgThread.GetThreadName().c_str();
        pthread_setname_np(pthread_self(), threadName);
    }

    if (SF_FAILED(pSelf->m_userMsgSock.SetupHost(c_daemonNameUserMsg, 5))) {
        SF_LOG_E("SetupHost() failed;");
        return NULL;
    }

    while (pSelf->m_userMsgThread.IsRunning()) {
        UnixSocket *pUserSock = SF_NEW UnixSocket;
        if (SF_FAILED(pSelf->m_userMsgSock.AcceptConnection(*pUserSock, 1000, TRUE))) {
            SF_DELETE pUserSock;
            continue;
        }

        std::string message;
        if (!pUserSock->ReceiveString(message, 1000)) {
            SF_LOG_E("Failed to receive message");
            SF_DELETE pUserSock;
            continue;
        }

        std::string tname;
        if (SF_SUCCESS(pSelf->getTaskName(message, tname))) {
            if (tname == c_taskUserBlockMsg) {
                pSelf->addReportQueue(message);
                SF_DELETE pUserSock;
            }
            else {
                SF_LOG_E("unsupported;");
                SF_DELETE pUserSock;
            }
        }
        else {
            SF_LOG_E("get task name failed;");
            SF_DELETE pUserSock;
        }
    }
    return NULL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
#ifdef LICENSING_PRODUCT
void* SfTaskMessageReceiver::threadQueueHandler(void *arg)
{
    SF_LOG_I("called;");

    if (arg == NULL) {
        SF_LOG_E("arg is NULL;");
        return NULL;
    }

    SfTaskMessageReceiver *pSelf = static_cast <SfTaskMessageReceiver*> (arg);
    if (pSelf != NULL) {
        const char *threadName = pSelf->m_queueHandleThread.GetThreadName().c_str();
        pthread_setname_np(pthread_self(), threadName);
    }

    while (pSelf->m_queueHandleThread.IsRunning()) {
        ReporterInfo* pInfo = NULL;
        pSelf->m_msgQueue.WaitPop(pInfo);
        if (pInfo == NULL) {
            SF_LOG_E("pInfo is NULL;");
            continue;
        }

        SF_LOG_I("Do nothing in Licensing Product");
        pSelf->freeReporterInfo(pInfo);
    }
    return NULL;
}
#else /* No LICENSING_PRODUCT */
void* SfTaskMessageReceiver::threadQueueHandler(void *arg)
{
    SF_LOG_I("called;");

    if (arg == NULL) {
        SF_LOG_E("arg is NULL;");
        return NULL;
    }

    SfTaskMessageReceiver *pSelf = static_cast <SfTaskMessageReceiver*> (arg);
    if (pSelf != NULL) {
        const char *threadName = pSelf->m_queueHandleThread.GetThreadName().c_str();
        pthread_setname_np(pthread_self(), threadName);
    }

    while (pSelf->m_queueHandleThread.IsRunning()) {
        ReporterInfo* pInfo = NULL;
        pSelf->m_msgQueue.WaitPop(pInfo);
        if (pInfo == NULL) {
            SF_LOG_E("pInfo is NULL;");
            continue;
        }

        if (!pInfo->SendFileFlag || pInfo->SysError == 1) {  /* SF_STATUS_SYSTEM_ERROR_IN_READ, SF_STATUS_NOT_ENOUGH_BUFFER */
            SF_LOG_E("SendFileFlag : %d / SysError : %d", pInfo->SendFileFlag, pInfo->SysError);
        }
        else if (GET_REPORT_OP(pInfo->SendFileFlag, ReportTask::SEND_FILE)) {
            SF_LOG_E("Security Report : ReportTask::SEND_FILE");
        }
        else if (GET_REPORT_OP(pInfo->SendFileFlag, ReportTask::SEND_SCANREPORT)) {
            SF_LOG_E("Security Report : ReportTask::SEND_SCANREPORT");
        }
        
        pSelf->m_recorder.SendLogToSCS(pInfo);
        pSelf->freeReporterInfo(pInfo);
    }
    return NULL;
}
#endif

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void *SfTaskMessageReceiver::threadInotifyHandler(void *arg)
{
    SF_LOG_W("called;");
    if (arg == NULL) {
        SF_LOG_E("invalid param;");
        return NULL;
    }

    const char *cStoragePath = tzplatform_mkpath(TZ_SYS_STORAGE, "");
    if (cStoragePath == NULL) {
        SF_LOG_E("Get storage path failed;");
        return NULL;
    }

    SfTaskMessageReceiver *pSelf = static_cast<SfTaskMessageReceiver*>(arg);
    if (pSelf != NULL) {
        const char *threadName = pSelf->m_inotifyMsgThread.GetThreadName().c_str();
        pthread_setname_np(pthread_self(), threadName);
    }
    
    Uint32 event_mask = IN_CREATE | IN_DELETE;
    if (!(pSelf->m_fsMonitor.Init()) || !(pSelf->m_fsMonitor.AddWatcher(cStoragePath, event_mask))) {
        SF_LOG_E("Initializing inotify handler or adding failed;");
        return NULL;
    }

    while (pSelf->m_inotifyMsgThread.IsRunning()) {
        const Int c_secondTimeout = 1;
        Int eResult = pSelf->m_fsMonitor.EventOccurred(c_secondTimeout);
        if (!eResult) {  // No event happened
            continue;
        } else if (eResult > 0) { // Some event(s) happened
            sync();

            SfFileSystemMonitor::SfFileSystemEvents FSevents = pSelf->m_fsMonitor.GetFileSystemEvents();
            for (size_t i = 0; i < FSevents.size(); ++i) {
                if (FSevents[i].mask & IN_ISDIR) {
                    SF_LOG_I("Size : %zu, Name : %s, Mask:%X", FSevents.size(), FSevents[i].name.c_str(), FSevents[i].mask);

                    if (FSevents[i].mask & IN_CREATE) {
                        SF_LOG_I("removable storage attached.;");
                    }

                    if (FSevents[i].mask & IN_DELETE) {
                        SF_LOG_I("removable storage dettached.;");
                        gsf_usb_device_off = TRUE;
                        SetUrgentEscapeScan(TRUE);
                    }
                }
            }
        }
    }
    pSelf->m_fsMonitor.RemoveAllWatchers();
    pSelf->m_fsMonitor.Finish();

    SF_LOG_W("exited;");
    return NULL;
}

