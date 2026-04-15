/*
SfRecorder.h
*/
#ifndef _SF_RECORDER_H_
#define _SF_RECORDER_H_

#include <map>

#include "libcore/SfStatus.h"
#include "libprimitive/SfFs.h"

#include "libprimitive/SfMutex.h"
#include "libprimitive/SfLockGuard.h"
#include "libprimitive/ISfThread.h"

#ifdef SAMSUNG_PRODUCT
#include <scs-common-plugin.h>
#endif

#define MAX_LEN 512

#define SF_TIME_BLOCK   "%c"
#define SF_TIME_Y_M_D   "%F"
#define SF_TIME_HHMMSS  "%T"
#define SF_TIME_WEEK    "%U"

#define GET_REPORT_OP(IN,OP) (((IN) & (1<<OP))>>OP)
#define SET_REPORT_OP(OP) (1<<OP)

#define SF_SCS_MODULE_ID_REL 950
#define SF_SCS_MODULE_ID_DBG 955
#define SF_SCS_SELF_MODULE_ID 755
#define REPORT_TYPE 1

#define CALLER_FIELD "sfpmd" 

typedef enum
{
    SF_CC_LOG_START          = 0,  ///< module is starting
    SF_CC_LOG_STOP           = 1,  ///< module is stopping
    SF_CC_LOG_DETECT         = 2,  ///< DETECT malware, etc...
    SF_CC_LOG_BLOCK          = 3,  ///< BLOCK m alware, etc...
    SF_CC_LOG_WARN           = 4,  ///< Warning
    SF_CC_LOG_INSTANT_ON     = 5,   ///< module is restring for power-on, etc.
    SF_CC_LOG_INSTANT_OFF    = 6,  ///< module is pausing for power-off, etc.
    SF_CC_LOG_INFO_TYPE_MAX
} SF_CC_LOG_INFO_TYPE;

struct SCSTaskEnum
{
    enum State
    {
        STOP     = 0,
        START    = 1,
        SKIP     = 2,
        SKIP_HASH = 3
    };
};

struct ReportTask
{
    enum Mode
    {
        SEND_FILE = 0,
        SEND_SCANREPORT = 2,
        SEND_STATE_MAX
    };
};

typedef struct _SelfReport {
std::map<std::string, std::string> reportData;
std::string description;
} SelfReport;

typedef struct _SfExtReport {
    _SfExtReport()
        : state(0)
        , caller(NULL)
        , callerLength(0)
        , fileType(NULL)
        , fileTypeLength(0)
        , fileName(NULL)
        , fileNameLength(0)
        , fileHash(NULL)
        , fileHashLength(0)
        , description(NULL)
        , descriptionLength(0)
        , embeddedFileName(NULL)
        , embeddedFileNameLength(0)
    {}

    int state;
    char* caller;
    size_t callerLength;
    char* fileType;
    size_t fileTypeLength;
    char* fileName;
    size_t fileNameLength;
    char* fileHash;
    size_t fileHashLength;
    char* description;
    size_t descriptionLength;
    char* embeddedFileName;
    size_t embeddedFileNameLength;
} SfExtReport;

typedef struct _ReporterInfo {
    _ReporterInfo()
        :EnvironmentsType(0)
        ,SendFileFlag( SET_REPORT_OP(ReportTask::SEND_FILE) )
        ,SysError(0)
        ,backupData(false)
    {}

    SfExtReport ExtInfo;
    int EnvironmentsType;
    int SendFileFlag;
    int SysError;
    char ReportSeq[20];
    char FileName[MAX_LEN];
    bool backupData;
} ReporterInfo;


#ifndef _
#define _(msg_id) sf_get_text(msg_id)
#endif 
extern "C" char *sf_get_text(const char *message);

class SfRecorder
{
    public:
        /**
        ****************************************************************************************************
        * @brief                Show Network Error Message Box
        * @return               void
        ****************************************************************************************************
        */
        void networkErrorPopupShow();
        
        /**
        ****************************************************************************************************
        * @brief                Send malware detection log to SCS
        * @param [in]  pInfo    information to be sent.
        * @return               SF_STATUS_OK if succeeded otherwise if failed.
        ****************************************************************************************************
        */
        SF_STATUS SendLogToSCS( ReporterInfo* pInfo ) const;

        /**
        ****************************************************************************************************
        * @brief                Send report to SCS
        * @param [in]  pInfo    information to be sent.
        * @return               SF_STATUS_OK if succeeded otherwise if failed.
        ****************************************************************************************************
        */
        SF_STATUS SendLogToSCS( SelfReport* sInfo ) const;

        /**
        ****************************************************************************************************
        * @brief                Check network(ethernet & wifi) status
        * @return               SF_STATUS_OK on conneced status SF_STATUS_FAIL on other status.
        ****************************************************************************************************
        */
        SF_STATUS checkNetworkStatus() const;
         
        /**
        ****************************************************************************************************
        * @brief                Get time string
        * @param [in]  format   time string format
        * @return               time string if succeeded, string size is 0 otherwise
        ****************************************************************************************************
        */
        static std::string GetFormattedTime( const char* format );

        /**
        ****************************************************************************************************
        * @brief                Get file hash value through SCS
        * @param [in] Info      Reporter information
        * @return               SF_STATUS_OK if succeeded otherwise if failed.
        ****************************************************************************************************
        */
        SF_STATUS GetScsHash( ReporterInfo* Info ) const;
        
    private:
        /**
        ****************************************************************************************************
        * @brief                Get whether system image is release version.
        * @return               SCS MODULE ID
        ****************************************************************************************************
        */
        int GetScsServerConfig() const;

        /**
        ****************************************************************************************************
        * @brief                Send security report to SCS
        * @param [in] Info      Reporter information
        * @return               SF_STATUS_OK if succeeded otherwise if failed.
        ****************************************************************************************************
        */
        SF_STATUS sendReport( ReporterInfo* pInfo ) const;

        /**
        ****************************************************************************************************
        * @brief                Send security report to SCS from SmartSecurity
        * @param [in] Info      Reporter information
        * @return               SF_STATUS_OK if succeeded otherwise if failed.
        ****************************************************************************************************
        */
        SF_STATUS sendReport( SelfReport* sInfo ) const;
};

/**
****************************************************************************************************
*
****************************************************************************************************
*/
namespace SecurityReport
{
enum REPORT_CODE{
    NONE = 0,
    CLEAR = 1,
    SHARED_CLEAR = 2,
    CCLOG_CLEAR = 3,
    GET_RW_SIZE = 4,
    GET_CC_SIZE = 5,
};

class ReportTaskWorker : public ISfThread<ReportTaskWorker>
{
public:
    ReportTaskWorker();
    ~ReportTaskWorker();
    SF_STATUS Execute(const REPORT_CODE operation);
    void ThreadFunction();
private:
    void HandleOperation(const REPORT_CODE operation);
    Uint64 CovertByteToKB(Uint64 byte);
private:
    int opcode = NONE;
    const char* taskname = "ReportTaskWorker";
};
}

#endif /* _SF_RECORDER_H_ */
