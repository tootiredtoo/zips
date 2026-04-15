/**
****************************************************************************************************
* @file SfKUEPSwitcher.h
* @brief Security framework [SF] class interface for tasks/plugins(antimalware,devicecontrol etc.).
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jan 14, 2015
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_TASK_KEUP_SWITCHER_H_
#define _SF_TASK_KEUP_SWITCHER_H_

// project
#include "libprimitive/SfFileSystemMonitor.h"
#include "libprimitive/ISfThread.h"

class SfKUEPSwitcher : public ISfThread<SfKUEPSwitcher>
{
public: // func
    SfKUEPSwitcher();
    ~SfKUEPSwitcher();

    SF_STATUS Execute();
    void ThreadFunction();

private: // func
    SF_STATUS SendDUIDToKernel() const;
    void FindUEPDisableFile();
}; // class SfTaskKUEOSwitcher

#endif /* _SF_TASK_KEUP_SWITCHER_H_ */
