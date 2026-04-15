/**
****************************************************************************************************
* @file SfFileSystemMonitor.cpp
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
// local
#include "SfFileSystemMonitor.h"

// project
#include "libcore/SfTime.h"

// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include <sys/types.h>

// system
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static const Int sc_badDesc          = -1;
static const Uint64 sc_inotifyEventSize = ( sizeof (struct inotify_event) );
static const Uint64 sc_bufferSize       = ( 1024 * ( sc_inotifyEventSize + 16 ) );

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfFileSystemMonitor::FsEvent::FsEvent()
    : mask( 0 )
    , name()
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfFileSystemMonitor::FsEvent::FsEvent( Uint32 inotifyMask, const std::string& c_name )
    : mask( inotifyMask )
    , name( c_name )
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfFileSystemMonitor::SfFileSystemMonitor()
    : m_watchDescriptors()
    , m_fd( sc_badDesc )
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfFileSystemMonitor::~SfFileSystemMonitor()
{
    RemoveAllWatchers( );
    Finish();
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfFileSystemMonitor::Init()
{
    m_fd = inotify_init();
    if ( sc_badDesc == m_fd )
    {
        SF_LOG_E( "Init inotify failed, error = [%s];", SF_GET_SYSTEM_ERROR( errno ) );
        return FALSE;
    }

    if ( sc_badDesc == fcntl( m_fd, F_SETFL, O_NONBLOCK ) )
    {
        SF_LOG_E( "setting desc failed, error = [%s];", SF_GET_SYSTEM_ERROR( errno ) );
        return FALSE;
    }

    return TRUE;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfFileSystemMonitor::AddWatcher( const std::string& c_path, Uint32 inotifyMasks )
{
     const Int c_watchDescriptor = inotify_add_watch( m_fd, c_path.c_str(), inotifyMasks );
     if ( sc_badDesc == c_watchDescriptor )
     {
        SF_LOG_E( "inotify_add_watch() failed, error = [%s];", SF_GET_SYSTEM_ERROR( errno ) );
        return FALSE;
     }

     m_watchDescriptors.push_back( c_watchDescriptor );
     return TRUE;
}


Bool SfFileSystemMonitor::RemoveAllWatchers( )
{
    int ret;
    Bool RetVal = TRUE;
    const size_t c_size = m_watchDescriptors.size();
    for ( size_t i = 0; i < c_size; i++ ) {
        ret = inotify_rm_watch( m_fd, m_watchDescriptors[ i ] );
	RetVal &= (ret == 0);
    }
    m_watchDescriptors.clear();

    return RetVal;
}


Bool SfFileSystemMonitor::Finish()
{
    Bool RetVal = TRUE;
    if (sc_badDesc != m_fd) {
	if (close( m_fd ) == -1) {
		RetVal = FALSE;	
	}
	m_fd = sc_badDesc;
	return RetVal;
    }

    return RetVal;
}



/**
****************************************************************************************************
*
****************************************************************************************************
*/
Int SfFileSystemMonitor::EventOccurred( Int secondsTimeout )
{
    if ( m_fd < 0 )
    {
        SfSleepMs( secondsTimeout );
        return SF_STATUS_FAIL;
    }

    struct timeval timeout;
    timeout.tv_sec = secondsTimeout;
    timeout.tv_usec = 0;

    fd_set fdSet;
    FD_ZERO( &fdSet );
    FD_SET( m_fd, &fdSet );
    return select( m_fd + 1, &fdSet, NULL, NULL, &timeout );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfFileSystemMonitor::SfFileSystemEvents SfFileSystemMonitor::GetFileSystemEvents()
{
    Char* pBuffer[ sc_bufferSize ] = { 0, };
    const ssize_t c_length = read( m_fd, pBuffer, sc_bufferSize );
    if ( c_length < 0 )
    {
        SF_LOG_E( "read() failed, error = [%s];", SF_GET_SYSTEM_ERROR( errno ) );
        return SfFileSystemEvents();
    }

    SfFileSystemEvents FSevents;
    for ( Uint64 i = 0; i < (Uint64)c_length; )
    {
        struct inotify_event* pEvent = ( struct inotify_event * )&pBuffer[ i ];
        if ( pEvent->len )
            FSevents.push_back( FsEvent( pEvent->mask, pEvent->name ) );

        SF_LOG_I( "event:%s;", pEvent->name );

        i += sc_inotifyEventSize + pEvent->len;
    }

    return FSevents;
}
