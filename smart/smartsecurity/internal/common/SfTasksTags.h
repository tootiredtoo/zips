/**
****************************************************************************************************
* @vd_noapi
* @file SfTaskTags.h
* @brief Security framework [SF] tags for tasks
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Sep 19, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_TASKS_TAGS_H_
#define _SF_TASKS_TAGS_H_

static const char c_daemonNameUserMsg[]         = "SfDaemon/UserMsg";
static const char c_daemonNameQueue[]           = "SfDaemon/Queue";

static const char c_taskTagRequester[]          = "Requester";
static const char c_taskTagTaskName[]           = "TaskName";
static const char c_taskUserBlockMsg[]          = "UserBlockMsg";

static const char c_taskTagState[]              = "State";
static const char c_taskTagResponse[]           = "Response";


/****************************************************************************************************/
static const char c_taskTagCaller[]             = "Report/Caller";
static const char c_taskTagPath[]               = "Report/Path";
static const char c_taskTagName[]               = "Report/Name";
static const char c_taskTagFileType[]           = "Report/FileType";
static const char c_taskTagDescription[]        = "Report/Decription";
static const char c_taskTagReportSeq[]          = "Report/ReportSeq";
/****************************************************************************************************/
static const char c_taskReportSendAlways[]      = "Action/Always";
static const char c_taskReportSendOnce[]        = "Action/Once";
static const char c_taskReportSendNo[]          = "Action/Cancel";
static const char c_taskReportFileSend[]        = "Action/FileSend";
static const char c_taskReportSendLogReport[]   = "Action/LogReport";
static const char c_taskReportBackupData[]      = "Action/BackupData";
/****************************************************************************************************/
static const char c_taskTagStatus[]             = "Status";
static const char c_taskStatusOk[]              = "Ok";
static const char c_taskStatusFail[]            = "Fail";
static const char c_taskStatusUsbDeviceOff[]    = "UsbDeviceOff";
static const char c_taskStatusNoSpace[]         = "NoSpace";
static const char c_ReportDataFileDes[]         = "DATA_FILE_DEC";
/****************************************************************************************************/

#define SF_SMART_SECURITY_PACKAGE_NAME "org.tizen.smart_security"

#endif /* !_SF_TASKS_TAGS_H_ */