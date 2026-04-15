/**
****************************************************************************************************
* @vd_noapi
* @file SfFileSystemMonitor.h
* @brief Security framework [SF] class interface for tasks/plugins(antimalware etc.).
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jan 14, 2015
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_FILE_SYSTEM_MONITOR_H_
#define _SF_FILE_SYSTEM_MONITOR_H_

// project
#include "libcore/SfDebug.h"

// system
#include <string>
#include <vector>
#include <sys/inotify.h>

class SfFileSystemMonitor
{
public: // type
    struct FsEvent
    {
        FsEvent();
        FsEvent( Uint32 inotifyMask, const std::string& c_name );

        Uint32 mask;
        std::string name;
    };

typedef std::vector < FsEvent > SfFileSystemEvents;
typedef std::vector < Int >     SfWatchDescriptors;

public:
    SfFileSystemMonitor();
    ~SfFileSystemMonitor();

    Bool Init();
    Bool AddWatcher( const std::string& c_path, Uint32 inotifyMasks );
    Bool RemoveAllWatchers();
    Bool Finish();
    Int EventOccurred( Int secondsTimeout );

    SfFileSystemEvents GetFileSystemEvents();

private: // members
    SfWatchDescriptors m_watchDescriptors;
    Int                m_fd;

}; // SfFileSystemMonitor

#endif /* _SF_FILE_SYSTEM_MONITOR_H_ */
