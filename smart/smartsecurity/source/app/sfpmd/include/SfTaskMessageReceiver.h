/**
****************************************************************************************************
* @file SfTaskMessageReceiver.h
* @brief Security framework [SF] receive message from kernel/user and handle message queue
* @author Euijin Je (euijin.je@samsung.com)
* @date Created Jul 10, 2017
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2017. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_TASK_MESSAGE_RECEIVER_H_
#define _SF_TASK_MESSAGE_RECEIVER_H_

#ifdef SHOW_SMARTSECURITY_POPUP
#include "common/SfPushNotification.h"
#endif //SHOW_SMARTSECURITY_POPUP
#include "libprimitive/UnixSocket.h"
#include "libsfkc/SfKernelConnection.h"
#include "libprimitive/SfSharedQueue.h"
#include "libprimitive/SfThread.h"
#include "libprimitive/SfFileSystemMonitor.h"

#include "SfRecorder.h"

#include <jsoncpp/json/json.h>

#define DISABLE   1
#define ENABLE    0

#define SF_MNT_INFO_SEP_SIZE 8
#define SF_MNT_INFO_SEP      "_UEP_MNT"
#define SF_MNT_INFO_MAX_LEN  10

enum MsgBoxType
{
    MSG_TYPE_OK_NORMAL = 2,
    MSG_NOTIFICATION = 5,
    MSG_TYPE_YES_NO  = 6,
    MSG_TYPE_OK      = 7,
};

typedef SfSharedQueue <ReporterInfo*> SfMessageQueue;

class SfTaskMessageReceiver
{
public:
    /**
    ****************************************************************************************************
    * @brief                    make SfTaskMessageReceiver instance
    * @return                   instance if succeeded, NULL otherwise
    ****************************************************************************************************
    */
    static SfTaskMessageReceiver* GetInstance();

    /**
    ****************************************************************************************************
    * @brief                    free SfTaskMessageReceiver instance
    * @return                   void
    ****************************************************************************************************
    */
    static void ReleaseInstance();

    /**
    ****************************************************************************************************
    * @brief                    Just send message to "SfDaemon/UserMsg" socket host
    *                           This message will be processed in threadQueueHandler() finally.
    * @param [in]  message      message to be sent.
    * @return                   SF_STATUS_OK if succeeded, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS addReportQueue( const std::string& message );

    /**
    ****************************************************************************************************
    * @brief                      compose security report
    * @param [in]  strCaller      caller
    * @param [in]  strFileType    file type
    * @param [in]  strPath        file path
    * @param [in]  strDescription description
    * @param [in]  strFileName    file name
    * @param [out] reporterinfo   variable to store above information
    * @return                     SF_STATUS_OK if success, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS composeSecurityReport( const char* strCaller, const char* strFileType, const char* strPath, 
                        const char* strDescription, const char* strFileName, ReporterInfo* pInfo ) const;

#ifdef SHOW_SMARTSECURITY_POPUP
    /**
    ****************************************************************************************************
    * @brief    Show Detailed window(blocked list window)
    *           It send message to smart_security UI app through capi-appfw-app-control framework.
    * @return   void
    ****************************************************************************************************
    */
    void kernelMessageDetailedShow();
#endif    
private:
    /**
    ****************************************************************************************************
    * @brief    class Constructor
    ****************************************************************************************************
    */
    SfTaskMessageReceiver();

    /**
    ****************************************************************************************************
    * @brief    class Destructor
    ****************************************************************************************************
    */
    ~SfTaskMessageReceiver();

    /**
    ****************************************************************************************************
    * @brief   run all thread used in SfTaskMessageReceiver
    * @return  0 if every thread run successfully or non-zero otherwise
    ****************************************************************************************************
    */
    int launchThreads();

    /**
    ****************************************************************************************************
    * @brief   stop all thread used in SfTaskMessageReceiver
    * @return  0 if every thread stop successfully or non-zero otherwise
    ****************************************************************************************************
    */
    int terminateThreads();

    /**
    ****************************************************************************************************
    * @brief                        Determine whether noitification should be shown for syscall
    *                               result
    * @param [in]  sysCallResult    syscall result
    * @param [out] result           Blocked Decription
    * @return                       TRUE if notification should be showm, FALSE otherwise
    ****************************************************************************************************
    */
    Bool shouldThrowNotification( Int32 sysCallResult, SF_STATUS& result ) const;

    /**
    ****************************************************************************************************
    * @brief                        Parsing Text and returning front text and rear test by delimiter
    * @param [in]  pszFullText      sourec Text
    * @param [in]  pDelimiter       delimiter symbol
    * @param [out] ppszFront        Front text; Will be allocated by malloc()
    * @param [out] ppszRear         Rear text; Willl be allocated by malloc()
    * @note                         You have to free ppszFront and ppszRear after being used. 
    * @return                       SF_STATUS_OK if success, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS ParseTextByDelimiter(const char* pszFullText, const char *pDelimiter, 
        char** ppszFront, char** ppszRear);
    
    /**
    ****************************************************************************************************
    * @brief                  analyze kernel packet and make information
    * @param [in]  pPacket    packet received from the kernel
    * @param [out] reportinfo variable to store above information
    * @return                 SF_STATUS_OK if success, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS composeKernelReporter( const SfPacket* pPacket, ReporterInfo* pReportInfo );

    /**
    ****************************************************************************************************
    * @brief                  parse user message and make information
    * @param [in]  message    message received from the user
    * @param [out] reportinfo variable to store above information
    * @return                 SF_STATUS_OK if success, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS composeUserReporter( const std::string& message, ReporterInfo* pReportInfo ) const;
	
    /**
    ****************************************************************************************************
    * @brief                    Make report's description content.
    * @param [in]  subject      description's subject
    * @param [in]  object       description's object
    * @param [in]  result       description's detaild content
    * @return                   composed description message 
    ****************************************************************************************************
    */
    std::string composeDescription( const char* subject, const char* object, const char* pExtra, SF_STATUS result ) const;

    /**
    ****************************************************************************************************
    * @brief                   free reporter info
    * @param [in] reporterinfo reporterinfo to free
    * @return                  Always SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS freeReporterInfo( ReporterInfo* pReporterInfo );

    /**
    ****************************************************************************************************
    * @brief                    Check Null for ReportPacket 
    * @param [in]  pReportOp    Kernel Packet
    * @return                   SF_STATUS_OK if Sucess, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS checkReportPacket(const SfOperationSecurityReport* pReportOp ) const;
    
    /**
    ****************************************************************************************************
    * @brief            get task name contained in message
    * @param [in] msg   message containing task name
    * @param [out] name task name extracted from message
    * @return           SF_STATUS_OK if success, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS getTaskName( const std::string& msg, std::string& name );

    /**
    ****************************************************************************************************
    * @brief  thread function for receiving kernel message
    * @return void
    ****************************************************************************************************
    */
    static void* receiveKernelMessage( void* arg );

    /**
    ****************************************************************************************************
    * @brief  thread function for receiving user message
    * @return void
    ****************************************************************************************************
    */
    static void* receiveUserMessage( void* arg );

    /**
    ****************************************************************************************************
    * @brief  thread function for handling message queue
    * @return void
    ****************************************************************************************************
    */
    static void* threadQueueHandler( void* arg );

    /**
    ****************************************************************************************************
    * @brief  thread function for handling inotify event
    * @return void
    ****************************************************************************************************
    */
    static void* threadInotifyHandler( void* arg );

private:
    static SfTaskMessageReceiver* m_pInstance;

    UnixSocket          m_userMsgSock;
    SfKernelConnection  m_kernelMsgSock;
    
    SfMessageQueue      m_msgQueue;
    SfRecorder          m_recorder;
    
    SfThread            m_userMsgThread;
    SfThread            m_kernelMsgThread;
    SfThread            m_queueHandleThread;
    SfThread            m_inotifyMsgThread;
    
    SfFileSystemMonitor m_fsMonitor;
};

#endif /* _SF_TASK_MESSAGE_RECEIVER_H_ */
