/**
****************************************************************************************************
* @file SfSignalHandler.cpp
* @brief Security framework [SF] implementation: ANSI C signal handling.
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jun 13, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifdef USE_SIGACTION	
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#endif 

// local
#include "libprimitive/SfSignalHandler.h"

/**
****************************************************************************************************
*
****************************************************************************************************
*/
volatile sig_atomic_t SfSignalHandler::m_interrupted = 0;

#ifdef USE_SIGACTION	
volatile sig_atomic_t SfSignalHandler::m_CallerPID = 0;

void SignalActionHandler(int sig, const siginfo_t *info, void *ucontext)
{
	pid_t caller_pid = 0;
	if (info) {
		caller_pid = info->si_pid;
	}
	SfSignalHandler::GetInstance().SetSignal( sig, caller_pid );
}
#else
/**
****************************************************************************************************
* @brief Functions
****************************************************************************************************
*/
void SignalHandler( Int32 sigNumber )
{
    SfSignalHandler::GetInstance().SetSignal( sigNumber );
}
#endif 
/**
****************************************************************************************************
* @brief Class SfSignalHandler
****************************************************************************************************
*/
SfSignalHandler::SfSignalHandler()
{
#ifdef USE_SIGACTION	
    m_signalHandler.sa_sigaction = (void (*)(int, siginfo_t*, void*))SignalActionHandler;
    m_signalHandler.sa_flags = SA_SIGINFO;
#else
    m_signalHandler.sa_handler = SignalHandler;
    m_signalHandler.sa_flags = 0;
#endif
    if ( sigemptyset( &m_signalHandler.sa_mask ) < 0 )
    {
        SF_LOG_E( "sigemptyset() failed;" );
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfSignalHandler::~SfSignalHandler()
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfSignalHandler::CatchSignal( Int32 signalNumber )
{
    if ( sigaction( signalNumber, &m_signalHandler, NULL ) < 0 )
    {
        SF_LOG_E( "sigaction() failed;" );
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfSignalHandler::IsSignalReceived()
{
    return ( 0 == m_interrupted ) ? FALSE : TRUE;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfSignalHandler::IsSignalReceived( Int32 signalNumber )
{
    return ( m_interrupted == signalNumber ) ? TRUE : FALSE;
}

#ifdef USE_SIGACTION
/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfSignalHandler::IsSignalMySelf( )
{
    return ( m_CallerPID == getpid() ) ? TRUE : FALSE;
}
#endif 



/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfSignalHandler::PrintReceivedSignal()
{
    if ( 0 != m_interrupted )
    {
        SF_LOG_W( "signal == %d", m_interrupted );
#ifdef USE_SIGACTION
        SF_LOG_W( "signal from pid: %d", m_CallerPID );
#endif 
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfSignalHandler::ResetReceivedSignal()
{
#ifdef USE_SIGACTION
    SetSignal( 0, 0);
#else	
    SetSignal( 0 );
#endif     
}

#ifdef USE_SIGACTION	
void SfSignalHandler::SetSignal( Int32 signalNumber, pid_t caller_pid )
{
    SfSignalHandler::m_interrupted = signalNumber;
    SfSignalHandler::m_CallerPID = caller_pid;
}

#else
/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfSignalHandler::SetSignal( Int32 signalNumber )
{
    SfSignalHandler::m_interrupted = signalNumber;
}
#endif

/**
****************************************************************************************************
*
****************************************************************************************************
*/
int SfSignalHandler::GetSenderPID()
{
#ifdef USE_SIGACTION
    return m_CallerPID;
#else
    return 0;
#endif    
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
int SfSignalHandler::GetSignal()
{
    return SfSignalHandler::m_interrupted;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
std::string SfSignalHandler::GetSenderProcessName()
{
    std::string name = DEFAULT_PROCESS_NAME;
#ifdef USE_SIGACTION
    std::string path = "/proc/" + std::to_string(m_CallerPID) + "/comm";
    std::ifstream file(path);
    if (file.is_open()) {
        std::getline(file, name);
    } 
#endif
    return name;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfSignalHandler& SfSignalHandler::GetInstance()
{
    static SfSignalHandler instance;
    return instance;
}
