/**
****************************************************************************************************
* @file main.cpp
* @brief Security framework [SF] Tizen UI application entry point
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created Aug 27, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
// local
#include "SfApplication.h"
#include "libcore/SfDebug.h"

// project
#include "libprimitive/SfSignalHandler.h"


/*
****************************************************************************************************
*
****************************************************************************************************
*/
int main(int argc, char* argv[])
{
    SfSignalHandler& sigHandler = SfSignalHandler::GetInstance();
    if ( SF_FAILED( sigHandler.CatchSignal( SIGPIPE ) ) )
        SF_LOG_E( "CatchSignal() failed;" );

    // Creates EFL application object with context that may be updated
    SfApplication application;

    SF_LOG_I(">> controller start ");
    // Invoke EFL application creation
    return application.Create(&argc, &argv);
}
