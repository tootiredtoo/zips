/**
****************************************************************************************************
* @vd_noapi
* @file SfPushNotification.h
* @brief Security framework [SF] class for Push Notofication
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Sep 24, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_PUSH_NOTIFICATION_H_
#define _SF_PUSH_NOTIFICATION_H_

// project
#include "libcore/SfCore.h"
#include "libprovider/SfSettings.h"

// system
#include <libintl.h>
#include <tzplatform_config.h>

#include <notification.h>
#include <notification_internal.h>
#include <notification_list.h>

class SfPushNotification
{
public: // methods
    SfPushNotification( char* const pAppName, char* const pTitle )
        : m_notification(NULL)
    {
        int noti_err = NOTIFICATION_ERROR_NONE;
        const int c_size = 255;
        char szInfoIconPath[c_size] = {0};
        snprintf(szInfoIconPath, c_size, "%s%s", SF_INFO_ICON_DIR, "/notification_icon_security.svg");

        m_notification = notification_create(NOTIFICATION_TYPE_NOTI);
        if(m_notification == NULL) 
        {
            SF_LOG_E("notification_create failed;");
        }

        noti_err = notification_set_pkgname(m_notification, pAppName);
        noti_err = notification_set_hide_timeout(m_notification, 10);
        noti_err = notification_set_auto_remove(m_notification, false);
        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_TITLE, pTitle, "TITLE", NOTIFICATION_VARIABLE_TYPE_NONE);
        noti_err = notification_set_image(m_notification, NOTIFICATION_IMAGE_TYPE_ICON, const_cast<char*>(szInfoIconPath));
        noti_err = notification_set_default_button(m_notification, (notification_button_index_e)0);

        if(noti_err != NOTIFICATION_ERROR_NONE) 
        {
            SF_LOG_E("notification setting failed;");
        }
    }

    ~SfPushNotification()
    {
        SF_LOG_I("Called;");
    }

    void SetTitleText( char* const pTitle)
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_TITLE, pTitle, "TITLE", NOTIFICATION_VARIABLE_TYPE_NONE);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("set title failed;");
        }
    }

    void ShowNotification( char* const pMessage )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_CONTENT, pMessage, "CONTENT", NOTIFICATION_VARIABLE_TYPE_NONE);
        noti_err = notification_post(m_notification);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("ShowNotification() failed;");
        }
    }

    void ShowNotification( char* const pMessage, int nDuration )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_CONTENT, pMessage, "CONTENT", NOTIFICATION_VARIABLE_TYPE_NONE);
        noti_err = notification_set_hide_timeout(m_notification, nDuration);
        noti_err = notification_post(m_notification);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("ShowNotification( , ) failed;");
        }
    }

    void ShowProgressNotification( char* const pMessage )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_CONTENT, pMessage, "CONTENT", NOTIFICATION_VARIABLE_TYPE_NONE);
        noti_err = notification_post(m_notification);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("ShowProgressNotification failed;");
        }
    }

    void SetProgressValue(const int value)
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_progress(m_notification, (double)value);
        noti_err = notification_post(m_notification);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("SetProgressValue failed;");
        }
    }

    void SetFirstButton( char* const pButtonName )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_add_button(m_notification, NOTIFICATION_BUTTON_1);
        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_BUTTON_1, pButtonName, "BUTTON_1", NOTIFICATION_VARIABLE_TYPE_NONE);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("SetFirstButton failed;");
        }
    }

    void SetSecondButton( char* const pButtonName )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_add_button(m_notification, NOTIFICATION_BUTTON_2);
        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_BUTTON_2, pButtonName, "BUTTON_2", NOTIFICATION_VARIABLE_TYPE_NONE);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("SetSecondButton failed;");
        }
    }

    void SetThirdButton( char* const pButtonName )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_add_button(m_notification, NOTIFICATION_BUTTON_3);
        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_BUTTON_3, pButtonName, "BUTTON_3", NOTIFICATION_VARIABLE_TYPE_NONE);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("SetThirdButton failed;");   
        }
    }
    
    void SetNotiMessage( char* const pMessage )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_text(m_notification, NOTIFICATION_TEXT_TYPE_CONTENT, pMessage, "CONTENT", NOTIFICATION_VARIABLE_TYPE_NONE);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("%s() failed;", __FUNCTION__);
        }
    }

    void SetDefaultBuffton( int nDefaultNo )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_default_button(m_notification, (notification_button_index_e)nDefaultNo);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("SetDefaultBuffton failed;");
        }
    }

    void RegisterEventCallback( event_handler_cb pCallback, void* pData )
    {
        int noti_err = NOTIFICATION_ERROR_NONE;

        noti_err = notification_set_display_applist( m_notification, NOTIFICATION_DISPLAY_APP_NOTIFICATION_TRAY |  NOTIFICATION_DISPLAY_APP_ACTIVE);
        noti_err = notification_post_with_event_cb(m_notification, pCallback, pData);

        if(noti_err != NOTIFICATION_ERROR_NONE)
        {
            SF_LOG_E("RegisterEventCallback failed;");
        }
    }

private: // members
    notification_h  m_notification;
}; // class SfPushNotification

#endif /* _SF_PUSH_NOTIFICATION_H_ */
