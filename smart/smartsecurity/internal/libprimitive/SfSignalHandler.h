/**
****************************************************************************************************
* @vd_noapi
* @file SfSignalHandler.h
* @brief Security framework [SF] ANSI C signal handling.
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jun 13, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_SIGNAL_HANDLER_H_
#define _SF_SIGNAL_HANDLER_H_

#define DEFAULT_PROCESS_NAME "no name"

/**
****************************************************************************************************
*
****************************************************************************************************
*/

#include <iostream>

// project
#include "libcore/SfDebug.h"

// system
#include "csignal"

/**
****************************************************************************************************
*
****************************************************************************************************
*/
class SfSignalHandler
{
private: // methods
    SfSignalHandler();
    SfSignalHandler( const SfSignalHandler& sigHanlder );
    SfSignalHandler operator=( const SfSignalHandler& sigHandler );

public: // methods
    ~SfSignalHandler();
    SF_STATUS CatchSignal( Int32 signalNumber );
    Bool IsSignalReceived();
    Bool IsSignalReceived( Int32 signalNumber );
    void PrintReceivedSignal();

    void ResetReceivedSignal();
#ifdef USE_SIGACTION	
    static void SetSignal( Int32 signalNumber, pid_t caller_pid );
    Bool IsSignalMySelf();
#else
    static void SetSignal( Int32 signalNumber );
#endif
    int GetSenderPID();
    std::string GetSenderProcessName();
    int GetSignal();
    static SfSignalHandler& GetInstance();

private: // members
    struct sigaction m_signalHandler;
    static volatile sig_atomic_t m_interrupted;
#ifdef USE_SIGACTION	
    static volatile sig_atomic_t m_CallerPID;
#endif 	

}; // class SfSignalHandler

/**
****************************************************************************************************
*
****************************************************************************************************
*/
#endif /* _SF_SIGNAL_HANDLER_H_ */
