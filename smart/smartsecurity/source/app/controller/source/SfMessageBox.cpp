/**
****************************************************************************************************
* @file SfMessageBox.cpp
* @brief Security framework [SF] Tizen UI Message Box
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Aug 27, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#include <vconf.h>
#include "SfMessageBox.h"
#include "SfReporterWindow.h"
#include "common/SfTasksTags.h"
#include "libprovider/SfSettings.h"
#include "libcore/SfDebug.h"
#include "efl_util.h"

#include <Key_Mode.h>
#include <jsoncpp/json/json.h>

/**
****************************************************************************************************
* @brief Window configuration callback string
****************************************************************************************************
*/
const char c_windowCallbackInfo[]    = "delete,request";
const char c_windowRotCallbackInfo[] = "wm,rotation,changed";

const static char* BUTTON1           = "button1";
const static char* BUTTON2           = "button2";
const static char* BUTTON3           = "button3";

static Bool bIsFirstSelect;
/*
****************************************************************************************************
*
****************************************************************************************************
*/
static Eina_Bool DefaultTimerCb( void* data )
{
    SF_LOG_I( "Called;" );
    
    SfMessageBox* pMsgBox = static_cast< SfMessageBox* >( data );    
    if ( pMsgBox != NULL )
    {
        if (pMsgBox->m_type == MSG_BOX_NO_TITLE_OK || 
            pMsgBox->m_type == MSG_BOX_TITLE_OK || 
            pMsgBox->m_type == MSG_BOX_NO_TITLE_OK_REPORTER)
        {
            SF_LOG_I( "1 Button,1 callback;" );
            pMsgBox->CallButton1Cb();
            pMsgBox->Destroy();
        }
        else if (pMsgBox->m_type == MSG_BOX_NO_TITLE_YES_NO || 
                 pMsgBox->m_type == MSG_BOX_TITLE_YES_NO ||
                 pMsgBox->m_type == MSG_BOX_NO_TITLE_YES_NO_DEFAULT_YES ||
                 pMsgBox->m_type == MSG_BOX_NO_TITLE_YES_NO_REPORTER)
        {
            SF_LOG_I( "1,2 Button,2 callback;" );
            pMsgBox->CallButton2Cb();
            pMsgBox->Destroy();
        }
        else if( pMsgBox->m_type == MSG_BOX_TITLE_REPORT_NOTIFICATION )
        {
            SF_LOG_I( "1,2,3 Button,3 callback;" );
            pMsgBox->CallButton3Cb();
            pMsgBox->Destroy();
        }
        else
        {
            SF_LOG_I( "else;" );
            pMsgBox->Destroy();
        }

        if (pMsgBox->GetNeedFree() == TRUE)
        {
            SF_DELETE pMsgBox;
        }
    }    
    return EINA_TRUE;
}
/*
****************************************************************************************************
*
****************************************************************************************************
*/
static void ReplaceString( std::string& text, const std::string& toFind,
                           const std::string& toReplace )
{
    size_t fPos = text.find( toFind );
    while ( fPos != std::string::npos )
    {
        text.replace( fPos, toFind.length(), toReplace );
        fPos = text.find( toFind, fPos + toReplace.length() );
    }
}
/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfMessageBox::SfMessageBox( MessageBoxType type )
    : m_windowName( "MessageBox" )
    , m_windowState ( SF_WINDOW_STATE_UNINITIALIZED )
    , m_isHidden( TRUE )
    , m_isNeedFree( FALSE )
    , m_pWindow( NULL )
    , m_pBox( NULL )
    , m_pPopup( NULL )   
    , m_pParentObject( NULL )
    , m_pButton1( NULL )
    , m_pButton2( NULL )
    , m_pButton3( NULL )
    , m_message() 
    , m_TTS_msg()
    , m_alertMessage(  )
    , m_timerHideMsgBox( NULL ) 
    , m_cbButton1( NULL )
    , m_cbButton2( NULL )
    , m_cbButton3( NULL )
    , m_pParamButton1( NULL )
    , m_pParamButton2( NULL )
    , m_pParamButton3( NULL )
    , m_DimType( SF_DIM_INIT )
    , m_pTouchEvent( NULL )
    , m_type( type ) 
{
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfMessageBox::~SfMessageBox()
{
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::SetButton1Callback( MsgBoxBtnCallback cb, void* pContext, void* pParam )
{
    m_cbButton1 = cb;
    m_pParamButton1->pContext = pContext;
    m_pParamButton1->pParam = pParam;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::SetButton2Callback( MsgBoxBtnCallback cb, void* pContext, void* pParam )
{
    m_cbButton2 = cb;
    m_pParamButton2->pContext = pContext;
    m_pParamButton2->pParam = pParam;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::SetButton3Callback( MsgBoxBtnCallback cb, void* pContext, void* pParam)
{
    m_cbButton3 = cb;
    m_pParamButton3->pContext = pContext;
    m_pParamButton3->pParam = pParam;
}
/*
****************************************************************************************************
*
****************************************************************************************************
*/
char *SfMessageBox::TtsInfoCallback(void* data, Evas_Object *obj)
{
    char *ret = NULL;
    SfMessageBox *pthis = static_cast<SfMessageBox*>(data);
    Eina_Strbuf *buf = eina_strbuf_new();
    
    if(bIsFirstSelect == TRUE)
    {
        eina_strbuf_append_printf(buf, "%s, %s", pthis->m_TTS_msg.c_str(), elm_object_text_get(obj));
    }
    else
    {
        eina_strbuf_append_printf(buf, "%s", elm_object_text_get(obj));
    }
    bIsFirstSelect = FALSE;
    ret = eina_strbuf_string_steal(buf);
    eina_strbuf_string_free(buf);
    eina_strbuf_free(buf);
    
    return ret;
}
/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMessageBox::Create(const char* title, MsgBoxRetType retType)
{
    SF_LOG_I( "Called;" );
    
    SF_STATUS result = SF_STATUS_FAIL;

    m_retType = retType;

    do
    {
        if ( GetWindowState() != SF_WINDOW_STATE_INITIALIZED )
        {
            bIsFirstSelect = FALSE;
            m_TTS_msg = title;
            m_TTS_msg += ".";
	    
            m_pParamButton1 = (MessageBoxButtonUserParam*)malloc(sizeof(MessageBoxButtonUserParam));
            memset(m_pParamButton1, 0x00, sizeof(MessageBoxButtonUserParam));
            
            m_pParamButton2 = (MessageBoxButtonUserParam*)malloc(sizeof(MessageBoxButtonUserParam));
            memset(m_pParamButton2, 0x00, sizeof(MessageBoxButtonUserParam));
            
            m_pParamButton3 = (MessageBoxButtonUserParam*)malloc(sizeof(MessageBoxButtonUserParam));
            memset(m_pParamButton3, 0x00, sizeof(MessageBoxButtonUserParam));

            SetWindowState( SF_WINDOW_STATE_INITIALIZED );

            m_pWindow = elm_win_add(NULL, m_windowName.c_str(), ELM_WIN_NOTIFICATION);
            efl_util_set_notification_window_level (m_pWindow, EFL_UTIL_NOTIFICATION_LEVEL_DEFAULT);
            elm_win_title_set(m_pWindow, m_windowName.c_str());
            elm_win_autodel_set(m_pWindow, EINA_TRUE);
            elm_win_alpha_set( m_pWindow, EINA_TRUE );
            elm_win_focus_highlight_style_set(m_pWindow, NULL);
            elm_win_focus_highlight_enabled_set(m_pWindow, EINA_TRUE);
            elm_win_aux_hint_add(m_pWindow, "wm.policy.win.need.dim", "1");

            int rots[] = { 0, 90, 180, 270 };
            elm_win_wm_rotation_available_rotations_set(m_pWindow, rots, (sizeof(rots) / sizeof(int)));
            evas_object_smart_callback_add( m_pWindow, c_windowRotCallbackInfo, SfWindowRotHandler, NULL); 
	    
            m_pBox = elm_box_add(m_pWindow);
            evas_object_size_hint_weight_set(m_pBox, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
            elm_win_resize_object_add(m_pWindow, m_pBox);

            std::string rTitle;
            if (title != NULL) {
                rTitle = std::string(title);
            }

            m_pPopup = elm_popup_add(m_pBox);
            elm_object_style_set(m_pPopup, "C_PopupBasic_WhiteBottom");
            elm_object_part_text_set(m_pPopup, "title,text", dgettext(SF_CONTROLLER_PACKAGE, rTitle.c_str())); 
            ea_apply_color_pick(m_pPopup);

            if ( m_pPopup != NULL )
            {
                evas_object_smart_callback_add( m_pPopup, "block,clicked", BlockClickedEventCb, this );
                evas_object_event_callback_add( m_pPopup, EVAS_CALLBACK_KEY_UP, KeyEventCb, this );

                if( m_retType == SF_DEFAULT )
                    m_pTouchEvent = ecore_event_handler_add( ECORE_EVENT_MOUSE_BUTTON_DOWN, TouchEventCb, this );
            }
            result = SF_STATUS_OK;
        }        
        else
        {
            SF_LOG_I("Already created");
        }
   
    } while (FALSE);              

    if ( SF_FAILED (result) )
    {
        Destroy();
    }

    return result;
}

SF_STATUS SfMessageBox::Create(const char* title, DimNeededType type, void* pObject, MsgBoxRetType retType)
{
    SF_LOG_I( "Called;" );
    
    SF_STATUS result = SF_STATUS_FAIL;

    m_retType = retType;

    do
    {
        if ( GetWindowState() != SF_WINDOW_STATE_INITIALIZED )
        {
            bIsFirstSelect = FALSE;
    	    m_TTS_msg = title;
    	    m_TTS_msg += ".";
	    
            m_pParamButton1 = (MessageBoxButtonUserParam*)malloc(sizeof(MessageBoxButtonUserParam));
            memset(m_pParamButton1, 0x00, sizeof(MessageBoxButtonUserParam));
            
            m_pParamButton2 = (MessageBoxButtonUserParam*)malloc(sizeof(MessageBoxButtonUserParam));
            memset(m_pParamButton2, 0x00, sizeof(MessageBoxButtonUserParam));
            
            m_pParamButton3 = (MessageBoxButtonUserParam*)malloc(sizeof(MessageBoxButtonUserParam));
            memset(m_pParamButton3, 0x00, sizeof(MessageBoxButtonUserParam));

            SetWindowState( SF_WINDOW_STATE_INITIALIZED );

            m_pWindow = elm_win_add(NULL, m_windowName.c_str(), ELM_WIN_NOTIFICATION);
            efl_util_set_notification_window_level (m_pWindow, EFL_UTIL_NOTIFICATION_LEVEL_DEFAULT);
            elm_win_title_set(m_pWindow, m_windowName.c_str());
            elm_win_autodel_set(m_pWindow, EINA_TRUE);
            elm_win_alpha_set( m_pWindow, EINA_TRUE );
            elm_win_focus_highlight_style_set(m_pWindow, NULL);
            elm_win_focus_highlight_enabled_set(m_pWindow, EINA_TRUE);

            int rots[] = { 0, 90, 180, 270 };
            elm_win_wm_rotation_available_rotations_set(m_pWindow, rots, (sizeof(rots) / sizeof(int)));
            evas_object_smart_callback_add( m_pWindow, c_windowRotCallbackInfo, SfWindowRotHandler, NULL); 

            m_pBox = elm_box_add(m_pWindow);
            evas_object_size_hint_weight_set(m_pBox, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
            elm_win_resize_object_add(m_pWindow, m_pBox);

            std::string rTitle;
            if (title != NULL) {
                rTitle = std::string(title);
            }

            m_pPopup = elm_popup_add(m_pBox);
            elm_object_style_set(m_pPopup, "C_PopupBasic_WhiteBottom");
            elm_object_part_text_set(m_pPopup, "title,text", dgettext(SF_CONTROLLER_PACKAGE, rTitle.c_str())); 
            ea_apply_color_pick(m_pPopup);

            m_DimType = type;
            m_pParentObject = (Evas_Object*)pObject;
            if ((m_DimType > SF_DIM_INIT) && (m_DimType < SF_DIM_MAX) && m_pParentObject)
            {
                if (m_DimType == SF_DIM_ISOLATED_LIST)
                {
                    elm_object_signal_emit(m_pParentObject, "theme,dimmed,percent,50", "");
                }
            }
            if ( m_pPopup != NULL )
            {
                evas_object_smart_callback_add( m_pPopup, "block,clicked", BlockClickedEventCb, this );
                evas_object_event_callback_add( m_pPopup, EVAS_CALLBACK_KEY_UP, KeyEventCb, this );

                if ( m_retType == SF_DEFAULT )
                    m_pTouchEvent = ecore_event_handler_add( ECORE_EVENT_MOUSE_BUTTON_DOWN, TouchEventCb, this );
            }
            result = SF_STATUS_OK;
        }        
        else
        {
            SF_LOG_I("Already created;");
        }
   
    } while (FALSE);              

    if ( SF_FAILED (result) )
    {
        Destroy();
    }

    return result;
}


/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMessageBox::Show(const char* message, Int timeOut)
{
    SF_LOG_I("Called;");
    if ( message == NULL )
    {
        SF_LOG_E("[invalid param];"); 
        return SF_STATUS_FAIL;    
    }

    std::string ttsMsg = message;
    m_message = message;

    switch ( m_type )
    {
        case MSG_BOX_TITLE_OK:
        case MSG_BOX_NO_TITLE_OK:
        case MSG_BOX_NO_TITLE_OK_REPORTER:
            m_message = "<align=center>" + m_message + "</align>";
            SetupWithoutTitleOk(ttsMsg.c_str());
            break;
        case MSG_BOX_NO_TITLE_YES_NO:
        case MSG_BOX_NO_TITLE_YES_NO_DEFAULT_YES:
        case MSG_BOX_NO_TITLE_YES_NO_REPORTER:
            m_message = "<align=center>" + m_message + "</align>";
            SetupWithoutTitleYesNo(ttsMsg.c_str());
            break;
        case MSG_BOX_TITLE_REPORT_NOTIFICATION:
            m_message = "<align=left>" + m_message + "</align>";
            ReplaceString(ttsMsg, "</br>", " ");
            SetupTitleReport(ttsMsg.c_str());
            break;
        default:
            SF_LOG_E( "[Unknown type(%d)];",m_type );
            return SF_STATUS_FAIL;
    }

    elm_object_text_set(m_pPopup, m_message.c_str()); 

    if ( NULL != m_timerHideMsgBox )
    {
        ecore_timer_freeze(m_timerHideMsgBox);
        ecore_timer_del(m_timerHideMsgBox);
        m_timerHideMsgBox = NULL;
    }
    if ( timeOut != 0 )
    {
        m_timerHideMsgBox = ecore_timer_add( (double)timeOut, DefaultTimerCb, (void *)this );
        if ( NULL == m_timerHideMsgBox ) 
            SF_LOG_E( "[adding ecore timer failed];" );
        ecore_timer_thaw(m_timerHideMsgBox);
    }
    
    if ( NULL != m_pPopup )
    {
        evas_object_show(m_pPopup);
    }
    if ( NULL != m_pBox )
    {
        evas_object_show(m_pBox);
    }
    if ( NULL != m_pWindow )
    {
        evas_object_show(m_pWindow);
    }
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMessageBox::Destroy()
{
    SF_LOG_I( "Called;" );    
    if ( GetWindowState() == SF_WINDOW_STATE_INITIALIZED )
    {
        if ( m_pParamButton1 != NULL )
        {
            free(m_pParamButton1);
            m_pParamButton1 = NULL;
        }
        if ( m_pParamButton2 != NULL )
        {
            free(m_pParamButton2);
            m_pParamButton2 = NULL;
        }
        if ( m_pParamButton3 != NULL )
        {
            free(m_pParamButton3);
            m_pParamButton3 = NULL;
        }

        switch (m_type)
        {
            case MSG_BOX_TITLE_OK:
            case MSG_BOX_NO_TITLE_OK:           
            case MSG_BOX_NO_TITLE_OK_REPORTER:
                DeleteButton( m_pButton1, NULL, Button1Cb);
                break;

            case MSG_BOX_NO_TITLE_YES_NO:
                /* fall through */
            case MSG_BOX_NO_TITLE_YES_NO_DEFAULT_YES:
            case MSG_BOX_NO_TITLE_YES_NO_REPORTER:
                DeleteButton( m_pButton1, NULL, Button1Cb);
                DeleteButton( m_pButton2, NULL, Button2Cb);
                break;
            case MSG_BOX_TITLE_REPORT_NOTIFICATION:
                DeleteButton( m_pButton1, NULL, Button1Cb);
                DeleteButton( m_pButton2, NULL, Button2Cb);
                DeleteButton( m_pButton3, NULL, Button3Cb);
                break;
            default:
                SF_LOG_E( "[Unknown type];" );
                break;
        }

        if ( m_timerHideMsgBox != NULL )
        {
            ecore_timer_freeze(m_timerHideMsgBox);
            ecore_timer_del(m_timerHideMsgBox);
            m_timerHideMsgBox = NULL;
        }

        if ((m_DimType > SF_DIM_INIT) && (m_DimType < SF_DIM_MAX) && m_pParentObject)
        {
            if (m_DimType == SF_DIM_ISOLATED_LIST)
            {
                elm_object_signal_emit(m_pParentObject, "theme,undim", "");
            }
        }
        if ( m_pPopup != NULL )
        {
            evas_object_smart_callback_del( m_pPopup, "block,clicked", BlockClickedEventCb );
            evas_object_event_callback_del( m_pPopup, EVAS_CALLBACK_KEY_UP, KeyEventCb );
            ecore_event_handler_del( m_pTouchEvent );
            SF_LOG_I("del key callback;");

            evas_object_del( m_pPopup );
            m_pPopup = NULL;
        }
	
        if ( m_pBox != NULL )
        {
            evas_object_del( m_pBox );
            m_pBox = NULL;
        }
        
        if ( m_pWindow != NULL )
        {
            evas_object_smart_callback_del( m_pWindow, c_windowRotCallbackInfo, SfWindowRotHandler );
            evas_object_del( m_pWindow );
            m_pWindow  = NULL;
        }

        SetWindowState ( SF_WINDOW_STATE_UNINITIALIZED );
    }
    else
    {
        SF_LOG_I("Not created;");
    }
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::KeyEventCb( void* pData, Evas* pEvas, Evas_Object* pEvasObj, void* pEvasEvent )
{
    SF_LOG_I("Called;");
    if ( pData == NULL || pEvasEvent == NULL )
    {
        SF_LOG_E( "[invalid param];" );
        return;
    }

    SfMessageBox* pWindow = static_cast<SfMessageBox*> (pData);
    Evas_Event_Key_Down* pEventKeyDown = (Evas_Event_Key_Down*)pEvasEvent;

    SF_LOG_I( "Keyname is [%s]", pEventKeyDown->keyname );

    if ( 0 == strcmp(pEventKeyDown->keyname, KEY_RETURN) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_EXIT) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_POWER) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_MENU) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_BT_VOICE) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_COLOR) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_MORE) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_PLAY_BACK) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_CHUP) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_CHDOWN) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_HOME) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_GUIDE) ) 
    {
        if ( pWindow ) 
        {
            if( pWindow->m_type == MSG_BOX_NO_TITLE_YES_NO_REPORTER || pWindow->m_type == MSG_BOX_NO_TITLE_OK_REPORTER 
                || pWindow->m_type == MSG_BOX_TITLE_REPORT_NOTIFICATION )
            {
                SF_LOG_I("\e[1;32mReport Message Box Clicked KeyName :[%s]\e[0m", pEventKeyDown->keyname);
            }

            if( pWindow->m_retType == SF_CLICK_BTN_1 )
            {
                SF_LOG_I( "CLICK BUTTON 1;" );
                pWindow->CallButton1Cb();
                pWindow->Destroy();
            }
            else if( pWindow->m_retType == SF_CLICK_BTN_2 )
            {
                SF_LOG_I( "CLICK BUTTON 2;" );
                pWindow->CallButton2Cb();
                pWindow->Destroy();
            }
            else
            {
                pWindow->Destroy();
            }
        }
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Eina_Bool SfMessageBox::TouchEventCb( void* data, int type, void* event )
{
    SF_LOG_I("Called;");

    Bool bBlockClick = FALSE;
    SfMessageBox* pWindow;
    Ecore_Event_Mouse_Button* pMouseEvent;

    pWindow = static_cast<SfMessageBox*> ( data );

    pMouseEvent = static_cast< Ecore_Event_Mouse_Button* >( event );
    if( !pMouseEvent )
    {
        return EINA_FALSE;
    }

    int rotate_status;

    vconf_get_int(VCONF_DISPLAY_ORIENTATION, &rotate_status);

    if (rotate_status != 0) // window is rotated
    {
        int px, py, pw, ph;

        px = py = pw = ph = 0;

        if( pWindow->m_pPopup )
        {
            evas_object_geometry_get( pWindow->m_pPopup, &px, &py, &pw, &ph );
        }

        if( py > pMouseEvent->x || py + ph < pMouseEvent->x )
            bBlockClick = TRUE;

        if( px > pMouseEvent->y || px + pw < pMouseEvent->y )
            bBlockClick = TRUE;
    }

    if( bBlockClick == TRUE )
    {
        if ( pWindow ) 
        {
            if( pWindow->m_type == MSG_BOX_TITLE_REPORT_NOTIFICATION )
            {
                SF_LOG_I( "send report" );
                SfReporterWindow::SendClickedMessage( c_daemonNameQueue, c_taskReportSendNo );
            }
            else if( pWindow->m_type == MSG_BOX_NO_TITLE_YES_NO
                  || pWindow->m_type == MSG_BOX_NO_TITLE_YES_NO_DEFAULT_YES
                  || pWindow->m_type == MSG_BOX_NO_TITLE_YES_NO_REPORTER )
            {
                SF_LOG_I( "scan window" );
            }

            if( pWindow->m_retType == SF_CLICK_BTN_1 )
            {
                SF_LOG_I( "CLICK BUTTON 1;" );
                pWindow->CallButton1Cb();
                pWindow->Destroy();
            }
            else if( pWindow->m_retType == SF_CLICK_BTN_2 )
            {
                SF_LOG_I( "CLICK BUTTON 2;" );
                pWindow->CallButton2Cb();
                pWindow->Destroy();
            }
            else
            {
                pWindow->Destroy();
            }
        }
        else
        {
            SF_LOG_E( "pWindow pointer has NULL pointer" );
        }
    }

    return EINA_TRUE;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::BlockClickedEventCb( void* pData, Evas_Object* pEvasObj, void* pEvasEvent )
{
    SfMessageBox* pWindow = static_cast<SfMessageBox*> (pData);

    if ( pWindow ) 
    {
        if( pWindow->m_type == MSG_BOX_TITLE_REPORT_NOTIFICATION )
        {
            SF_LOG_I( "send report" );
            SfReporterWindow::SendClickedMessage( c_daemonNameQueue, c_taskReportSendNo );
        }
        else if( pWindow->m_type == MSG_BOX_NO_TITLE_YES_NO
              || pWindow->m_type == MSG_BOX_NO_TITLE_YES_NO_DEFAULT_YES
              || pWindow->m_type == MSG_BOX_NO_TITLE_YES_NO_REPORTER )
        {
            SF_LOG_I( "scan window" );
        }

        if( pWindow->m_retType == SF_CLICK_BTN_1 )
        {
            SF_LOG_I( "CLICK BUTTON 1;" );
            pWindow->CallButton1Cb();
            pWindow->Destroy();
        }
        else if( pWindow->m_retType == SF_CLICK_BTN_2 )
        {
            SF_LOG_I( "CLICK BUTTON 2;" );
            pWindow->CallButton2Cb();
            pWindow->Destroy();
        }
        else
        {
            pWindow->Destroy();
        }
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::SfWindowRotHandler(void* pData, Evas_Object* pObject, void* pEvent)
{
    int lfd_rotate_status = 0;
    int current_degree    = 0;
    
    vconf_get_int(VCONF_DISPLAY_ORIENTATION, &lfd_rotate_status);

    current_degree = elm_win_rotation_get(pObject);

    if (current_degree != 0)
    {
        elm_object_scale_set(pObject, 0.5625); // scale

        if (lfd_rotate_status != 0)
        {
            elm_object_style_set(pObject, "portrait");
        }
    }
    else
    {
        elm_object_scale_set(pObject, 1.0);  // scale
        elm_object_style_set(pObject, "default");
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMessageBox::Hide()
{
    SF_LOG_I( "Called;" );
    m_isHidden = TRUE;

    if ( NULL != m_pButton3 )
    {
        evas_object_hide(m_pButton3);
    }

    if ( NULL != m_pButton2 )
    {
        evas_object_hide(m_pButton2);
    }

    if ( NULL != m_pButton1 )
    {
        evas_object_hide(m_pButton1);
    }

    if ( NULL != m_pPopup )
    {
        evas_object_hide(m_pPopup);
    }

    if ( NULL != m_pBox )
    {
        evas_object_hide(m_pBox);
    }
    
    if ( NULL != m_pWindow )
    {
        evas_object_hide(m_pWindow);
    }
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMessageBox::SetupWithoutTitleOk( const char* message)
{
    SF_LOG_I( "Called;" );
    AddButton( m_pButton1, NULL, BUTTON1, "COM_SID_OK", message, NULL, Button1Cb );
    return SF_STATUS_OK;
}



/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMessageBox::SetupWithoutTitleYesNo( const char* message )
{
    SF_LOG_I( "Called;" );
    AddButton( m_pButton1, NULL, BUTTON1, "COM_SID_YES", message, NULL, Button1Cb);
    AddButton( m_pButton2, NULL, BUTTON2, "COM_SID_NO", message, NULL, Button2Cb);
    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfMessageBox::SetupTitleReport( const char* message )
{
    SF_LOG_I( "Called;" );
    AddButton( m_pButton1, NULL, BUTTON1, "COM_SID_ALWAYS", message, NULL, Button1Cb );
    AddButton( m_pButton2, NULL, BUTTON2, "COM_SID_ONCE", message, NULL, Button2Cb );
    AddButton( m_pButton3, NULL, BUTTON3, "COM_SID_CANCEL", message, NULL, Button3Cb );
    return SF_STATUS_OK;
}
/**
****************************************************************************************************
* write something
****************************************************************************************************
*/
void SfMessageBox::RefreshMessageLable( const char* message)
{
    SF_LOG_I("\e[1;33m###New Msg : %s\e[0m",message );
    std::string m_Align_prefix = "<align=center>";
    std::string m_Align_suffix = "</align>";

    m_message = message;
    m_message = m_Align_prefix + m_message + m_Align_suffix;
    elm_object_text_set(m_pPopup, m_message.c_str());
    evas_object_show(m_pPopup);
}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::AddButton( Evas_Object* pButtonObj, Evas_Object* pImageObj, std::string ButtonIndex, const char* ButtonName, 
                                const char* message, const char* ButtonIcon, Evas_Smart_Cb func )
{
    const char* strButtonName = dgettext(SF_CONTROLLER_PACKAGE, ButtonName);

    pButtonObj = elm_button_add(m_pPopup);
    elm_object_style_set(pButtonObj, "C_ButtonBasic_WhiteText");
    elm_object_text_set(pButtonObj, strButtonName );
    elm_object_part_content_set(m_pPopup, ButtonIndex.c_str(), pButtonObj);
    
    evas_object_smart_callback_add( pButtonObj, "clicked", func, this );

    if( ButtonIndex == BUTTON1 )
    {
        bIsFirstSelect = TRUE;
        m_TTS_msg = m_TTS_msg + message + ".";
        elm_access_info_cb_set( pButtonObj, ELM_ACCESS_INFO, TtsInfoCallback, this);
        elm_object_focus_allow_set( pButtonObj, EINA_TRUE );
    }
    
    if(  NULL != pButtonObj )
        evas_object_show( pButtonObj );
}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::DeleteButton( Evas_Object* pButtonObj, Evas_Object* pImageObj, Evas_Smart_Cb func )
{
    if( pButtonObj )
    {
        evas_object_smart_callback_del( pButtonObj, "clicked", func );
        evas_object_del(pButtonObj);
        pButtonObj = NULL;
    }
}
/*
****************************************************************************************************
*
****************************************************************************************************
*/

void SfMessageBox::Button1Cb(void* pData, Evas_Object* pObject, void* pEvent)
{
    SF_LOG_I( "Called;" );
    if (NULL != pData)
    {
        SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData);
        if ( pMsgBox != NULL )
        {
            pMsgBox->Hide();
            pMsgBox->CallButton1Cb();
            pMsgBox->Destroy();
        }
    }        
    else
    {
        SF_LOG_E("[Invalid param];");
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::CallButton1Cb()
{
    SF_LOG_I("Called;");
    if ( m_cbButton1 != NULL )
    {
        MessageBoxButtonCbParam* pData = (MessageBoxButtonCbParam*)malloc(sizeof(MessageBoxButtonCbParam));                
        pData->pUserParam= m_pParamButton1;
        pData->pSfMessageBox = this;
        SF_LOG_I("Called;");
        m_cbButton1(pData);
        free(pData);
        pData = NULL;
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::Button2Cb(void* pData, Evas_Object* pObject, void* pEvent)
{
    if (NULL != pData)
    {
        SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData);
        if ( pMsgBox != NULL )
        {
            pMsgBox->Hide();
            pMsgBox->CallButton2Cb();
            pMsgBox->Destroy();
        }
    }        
    else
    {
        SF_LOG_E("[invalid param];");
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::CallButton2Cb()
{
    if ( m_cbButton2 != NULL )
    {
        MessageBoxButtonCbParam* pData = (MessageBoxButtonCbParam*)malloc(sizeof(MessageBoxButtonCbParam));                
        pData->pUserParam = m_pParamButton2;
        pData->pSfMessageBox = this;
        SF_LOG_I("Call callback;");
        m_cbButton2(pData);
        free(pData);
        pData = NULL;
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::Button3Cb(void* pData, Evas_Object* pObject, void* pEvent)
{
    if (NULL != pData)
    {
        SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData);
        if ( pMsgBox != NULL )
        {
            pMsgBox->Hide();
            pMsgBox->CallButton3Cb();
            pMsgBox->Destroy();
        }
    }        
    else
    {
        SF_LOG_E("[invalid param];");
    }
}
/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::CallButton3Cb()
{
    if ( m_cbButton3 != NULL )
    {
        MessageBoxButtonCbParam* pData = (MessageBoxButtonCbParam*)malloc(sizeof(MessageBoxButtonCbParam));                
        pData->pUserParam = m_pParamButton3;
        pData->pSfMessageBox = this;
        SF_LOG_I("Call callback;");
        m_cbButton3(pData);
        free(pData);
        pData = NULL;
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_WINDOW_STATE SfMessageBox::GetWindowState() const
{
    return m_windowState;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::SetWindowState(SF_WINDOW_STATE state)
{
    m_windowState = state;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfMessageBox::IsHidden() const
{
    return m_isHidden;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfMessageBox::SetHidden(Bool isHidden)
{
    m_isHidden = isHidden;
}
