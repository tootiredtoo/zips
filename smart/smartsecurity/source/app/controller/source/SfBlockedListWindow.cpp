/**
****************************************************************************************************
* @file SfBlockedListWindow.cpp
* @brief Security framework [SF] Blocked list window class implementation
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created Aug 29, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#include "SfBlockedListWindow.h"
#include "SfReporterWindow.h"
#include "SfEflIncludes.h"
#include "libcore/SfDebug.h"
#include "libprovider/SfSettings.h"

#include "libprimitive/SfSharedFile.h"
#include "libprimitive/SfStringUtils.h"
#include "common/SfTasksTags.h"
#include "common/SfJSONTags.h"
#include "libprimitive/SfFs.h"

// system
#include <jsoncpp/json/json.h>
#include <unistd.h>

#include <vconf.h>
#include <cstdlib>
#include <cstring>
#include <app.h>
#include <aul.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <Key_Mode.h>

#define SF_ELM_SCALE_SIZE(a, b) ((int)(((double)(a) * b) / elm_app_base_scale_get() + 0.5))

/**
****************************************************************************************************
* @brief Window configuration callback string
****************************************************************************************************
*/
const char c_windowCallbackInfo[] = "delete,request";
const char c_windowRotCallbackInfo[] = "wm,rotation,changed";
static Bool bIsFirstSelect;

/**
****************************************************************************************************
* @brief                    Replace all occurences of search string
* @param [in,out] text      String to find and replace in
* @param [in] toFind        String to be found
* @param [in] toReplace     String to replace with
* @return
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

Bool SfBlockedListWindow::m_isFromKernel = FALSE;
Bool SfBlockedListWindow::m_AlreadyShowFromKernel = FALSE;
Bool SfBlockedListWindow::m_AlreadyEntered = FALSE;

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfBlockedListWindow::SfBlockedListWindow( const std::string& windowName )
    : m_windowName( windowName )
    , m_showMenuTitle( "Blocked List" )
    , m_windowState( SF_WINDOW_STATE_UNINITIALIZED )
    , m_isHidden( TRUE )
    , m_pWindow( NULL )
    , m_pBox( NULL )
    , m_pPopup( NULL )
    , m_pTable( NULL )
    , m_pBodyLabel( NULL )
    , m_pCloseButton ( NULL )
    , m_pList( NULL )
    , m_pItemClass( NULL )
    , m_items()
    , m_blockedList()
    , m_pTouchEvent( NULL )
    , m_ListWindowType( SF_WINDOW_TYPE_BLOCKED_LIST )
{
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfBlockedListWindow::~SfBlockedListWindow()
{
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
static void GetBlockedList(SfFilesList& files)
{
    SfSharedFile sharedFile;
    if ( !sharedFile.open( SF_SFPMD_BLOCKED_RESOURCES, "r" ) )
    {
        SF_LOG_E( "open() failed;" );
		sharedFile.close();
        return;
    }

    std::string fileContent;
    if ( !sharedFile.readFileContent( fileContent ) )
    {
        SF_LOG_E( "reading failed;" );
		sharedFile.close();
        return;
    }

    try
    {
        Json::Value root;
        Json::Reader reader;
        if ( !reader.parse( fileContent, root, false ) )
        {
            SF_LOG_E( "Failed to parse %s, error = %s;",
                      SF_SFPMD_BLOCKED_RESOURCES, reader.getFormatedErrorMessages().c_str() );
            sharedFile.close();
			return;
        }
        
        for ( Uint i = 0; i < root[ c_tagItems ].size(); ++i )
                files.push_back( root[ c_tagItems ][ i ].asString() );
    }
    catch(Json::Exception& e) 
    {
        SF_LOG_E("Exception from Json exception[%s];", e.what());
		sharedFile.close();
    }
	sharedFile.close();
    return;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::Create()
{
    SF_LOG_I("Called,%s;", m_windowName.c_str()); 
    SF_STATUS result = SF_STATUS_OK;
    if ( GetWindowState() != SF_WINDOW_STATE_INITIALIZED )
    {
        do
        {   
            SetWindowState( SF_WINDOW_STATE_INITIALIZED );
            m_oMode = ua_UI_orientation_get();
            m_blockedList.clear();
            GetBlockedList(m_blockedList);
            if (SF_FAILED( CreateWindowObject(_("TV_SID_MONITORING_RESULTS"),
                                            _("TV_SID_MIX_BLOCKED_ITEMS"),
                                              "C_PopupBasic_WhiteRightLarge")))
            {
                SF_LOG_E("Can not create window onbject");
                result = SF_STATUS_FAIL;
                break;
            }
        
            /**
            * @brief Trying to create list view object for blocked list
            */
            if (SF_FAILED(CreateListViewObject()))
            {
                SF_LOG_E("Can not create list view object");
                result = SF_STATUS_FAIL;
                break;
            }
        
            /**
            * @brief Trying to create Close button object
            */
            if (SF_FAILED(CreateCloseButtonObject()))
            {
                SF_LOG_E("Can not create close button object");
                result = SF_STATUS_FAIL;
                break;
            }
    
            if ( m_pPopup != NULL )
            {
                evas_object_event_callback_add( m_pPopup, EVAS_CALLBACK_KEY_DOWN, KeyEventCb, this );
                SF_LOG_I("set key callback;");
            }

            SetContent(m_blockedList);
	    bIsFirstSelect = FALSE;
            
            result = SF_STATUS_OK;
        } while (FALSE);
    }
    else
    {
        SF_LOG_I ( "Already Created");
    }    

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
SF_STATUS SfBlockedListWindow::Destroy()
{
    SF_LOG_I("Called;");
    if ( GetWindowState() == SF_WINDOW_STATE_INITIALIZED )
    {
        DestroyCloseButtonObject();    
        DestroyListViewObject();   

        if ( m_pPopup != NULL )
        {
            evas_object_event_callback_del( m_pPopup, EVAS_CALLBACK_KEY_DOWN, KeyEventCb );
            SF_LOG_I("set key callback;");
        }   
        
        DestroyWindowObject();
        SetHidden ( TRUE );
        SetWindowState( SF_WINDOW_STATE_UNINITIALIZED );

        m_isFromKernel = FALSE;
        m_AlreadyShowFromKernel = FALSE;
        m_AlreadyEntered = FALSE;
        
    }
    else
    {
        SF_LOG_I ( "Not Created");
    }
    
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::KeyEventCb( void* pData, Evas* pEvas, Evas_Object* pEvasObj, void* pEvasEvent )
{
    SF_LOG_I("Called;");
    
    if ( pData == NULL || pEvasEvent == NULL )
    {
        SF_LOG_E( "pData = NULL || pEvasEvent = NULL" );
        return;
    }

    Evas_Event_Key_Down* pEventKeyDown = (Evas_Event_Key_Down*)pEvasEvent;
    if ( 0 == strcmp(pEventKeyDown->keyname, KEY_RETURN) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_EXIT) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_GUIDE) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_POWER) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_MENU) || 
         0 == strcmp(pEventKeyDown->keyname, KEY_HOME) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_BT_VOICE) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_COLOR) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_MORE) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_PLAY_BACK) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_CHUP) ||
         0 == strcmp(pEventKeyDown->keyname, KEY_CHDOWN) ) 
    {
        SfBlockedListWindow* pWindow = static_cast<SfBlockedListWindow*> (pData);
        SF_LOG_I( "key:%s;", pEventKeyDown->keyname );
        
        if ( pWindow ) 
        {
            pWindow->Destroy();
        }
    }

    //SF_LOG_I( "Keyname is [%s]", pEventKeyDown->keyname );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Eina_Bool SfBlockedListWindow::TouchEventCb( void* data, int type, void* event )
{
    SF_LOG_I("Called;");

    Bool bBlockClick = FALSE;
    SfBlockedListWindow* pWindow;
    Ecore_Event_Mouse_Button* pMouseEvent;

    pWindow = static_cast<SfBlockedListWindow*> ( data );

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
            pWindow->Destroy();
        }
    }

    return EINA_TRUE;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::BlockClickedEventCb( void* pData, Evas_Object* pEvasObj, void* pEvasEvent )
{
    SF_LOG_I("Called;");
    
    SfBlockedListWindow* pWindow = static_cast<SfBlockedListWindow*> (pData);
      
    if ( pWindow ) 
    {
        pWindow->Destroy();
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::Show()
{
    SF_LOG_I("Called;");

    if (m_isFromKernel == TRUE)
    {
        if (m_AlreadyEntered == TRUE)
        {
            RefreshAllData();
        }
        else if (m_AlreadyShowFromKernel == TRUE)
        {
            RefreshAllData();
        }
        else
        {
            m_AlreadyShowFromKernel = TRUE;
        }
    }

    if (m_pCloseButton)
    {
        evas_object_show( m_pCloseButton );
    }
    
    if (m_pBodyLabel)
    {
        evas_object_show(m_pBodyLabel);
    }

    if ( m_pList != NULL )
    {
        evas_object_show(m_pList);
    }

    if ( m_pRectBottom != NULL )
    {
        evas_object_show(m_pRectBottom);
    }

    if (m_pTable)
    {
        evas_object_show(m_pTable);
    }

    if ( m_pPopup != NULL )
    {
        evas_object_show(m_pPopup);
    }

    if ( m_pBox != NULL )
    {
        evas_object_show(m_pBox);
    }
    
    if ( m_pWindow != NULL )
    {
        evas_object_show(m_pWindow);
    }

    UpdateTtsText();    
    UpdateControlStatus();
    
    SetHidden( FALSE );
    return SF_STATUS_OK;
}


/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::Hide()
{
    SF_LOG_I("Called;");
    
    if ( m_pCloseButton != NULL )
    {
        evas_object_hide( m_pCloseButton );
    }  

    if ( m_pBodyLabel != NULL )
    {
        evas_object_hide(m_pBodyLabel);
    }

    if ( m_pList != NULL )
    {
        evas_object_hide( m_pList );
    }

    if ( m_pRectBottom != NULL )
    {
        evas_object_hide( m_pRectBottom );
    }

    if (m_pTable)
    {
        evas_object_hide(m_pTable);
    }

    if ( m_pPopup != NULL )
    {
        evas_object_hide(m_pPopup);
    }

    if ( m_pBox != NULL )
    {
        evas_object_hide(m_pBox);
    }
    
    if ( m_pWindow != NULL )
    {
        evas_object_hide(m_pWindow);
    }

    SetHidden( TRUE );
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::CreateCloseButtonObject()
{
    SF_LOG_I("Called;");

    SF_STATUS result = SF_STATUS_OK;
    do
    {
        m_pCloseButton = elm_button_add(m_pPopup);
        if ( m_pCloseButton == NULL )
        {
            SF_LOG_E( "m_pCloseButton == NULL;" );
            result = SF_STATUS_FAIL;
            break;
        }
 
        elm_object_style_set(m_pCloseButton, "C_ButtonBasic_WhiteText");
        elm_object_text_set(m_pCloseButton, _("COM_SID_CLOSE"));
        elm_object_part_content_set(m_pPopup, "button2", m_pCloseButton);      
        elm_object_focus_allow_set(m_pCloseButton, EINA_TRUE);
                
        evas_object_smart_callback_add(m_pCloseButton, "clicked", SfButtonCloseHandler, this);      
        
    } while ( FALSE );


    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::DestroyCloseButtonObject()
{
    SF_LOG_I("Called;");
    if ( m_pCloseButton != NULL )
    {
        evas_object_smart_callback_del(m_pCloseButton, "clicked", SfButtonCloseHandler);
        SF_LOG_I("del button callback");

        evas_object_del(m_pCloseButton);
        m_pCloseButton = NULL;        
    }

    return SF_STATUS_OK;
}


/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SfButtonCloseHandler(void* pData, Evas_Object* pObject, void* pEvent)
{
    SF_LOG_I("Clicked;");
    if ( pData != NULL )
    {
        
        SfBlockedListWindow* pHandle = static_cast<SfBlockedListWindow*> (pData);
        if ( pHandle != NULL )
        {
            SF_LOG_I("clicked %p,type:%d;", pData,pHandle->m_ListWindowType );
            pHandle->Destroy();
        }
    }

}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::SetContent( const SfFilesList& content )
{
    SF_LOG_I("Called;");
    size_t contentSize = content.size();
    m_items.clear();    

    m_items.resize( contentSize );
    size_t i = 0;
    for ( SfFilesList::const_reverse_iterator rit = content.rbegin(); rit != content.rend(); ++rit )
    {
        m_items[ i ].path = *rit;
        m_items[ i ].name = FindFileNameFromPath(m_items[ i ].path);
        ++i;
    }
    SF_LOG_I( "%zu items;", contentSize );

    RefreshItems();

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
* 
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::RefreshItems()
{
    SF_LOG_I("Called;");

    if( m_pList == NULL ) 
    {
        return SF_STATUS_FAIL;
    }
    
    ClearList();
    
    // add items to the list
    for ( size_t i = 0; i < m_items.size(); ++i )
    {
        m_items[ i ].status = true;
        m_items[ i ].pItem = elm_genlist_item_append( m_pList, m_pItemClass,
                                                      (void *)(&m_items[ i ]),
                                                      NULL, ELM_GENLIST_ITEM_NONE,
                                                      SelectItemCallback, &m_items[ i ] );
    }
    SF_LOG_I( "Added %zu items;", m_items.size() );

    elm_genlist_realized_items_update(m_pList);
    

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::RefreshAllData()
{
    SF_LOG_I("Called;");

    const Uint32 c_bufSize = 1024;
    char szMessage[ c_bufSize ] = {0};
    
    m_blockedList.clear();
    GetBlockedList(m_blockedList);
    SetContent(m_blockedList);
    
    std::string strText = dgettext(SF_CONTROLLER_PACKAGE, "TV_SID_MIX_BLOCKED_ITEMS");
    std::string strNumber = SfStringUtils::NumberToString(m_blockedList.size());
    SF_LOG_I("size:%s;", strNumber.c_str());
    ReplaceString(strText, "<<A>>", strNumber);
    int ret = snprintf(szMessage, c_bufSize, "<align=left>%s</align>", strText.c_str());
    if ( ret < 0 || ret >= (int)c_bufSize )
    {
        SF_LOG_E( "snprintf() failed;" );
        return SF_STATUS_FAIL;
    }
    elm_object_text_set(m_pBodyLabel, szMessage);  
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::CreateListViewObject()
{
    SF_LOG_I("Called;");
    
    SF_STATUS result = SF_STATUS_OK;
    do
    {
        m_pList = elm_genlist_add(m_pPopup);
        if ( m_pList == NULL )
        {
            SF_LOG_E( "Can not create list.;");
            result = SF_STATUS_FAIL;
            break;
        }
        evas_object_size_hint_min_set( m_pList, ELM_SCALE_SIZE(875), ELM_SCALE_SIZE(456) );
        evas_object_size_hint_max_set( m_pList, ELM_SCALE_SIZE(875), ELM_SCALE_SIZE(456) );
        evas_object_size_hint_weight_set(m_pList, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(m_pList, EVAS_HINT_FILL, EVAS_HINT_FILL);

        elm_genlist_select_mode_set(m_pList, ELM_OBJECT_SELECT_MODE_ALWAYS); 
        elm_object_style_set(m_pList, "C_Scrollbar_White");
        elm_object_scroll_item_loop_enabled_set(m_pList, EINA_TRUE);
        elm_genlist_highlight_mode_set(m_pList, EINA_FALSE);

        m_pRectBottom = evas_object_rectangle_add( evas_object_evas_get(m_pPopup) );
        evas_object_size_hint_min_set( m_pRectBottom, ELM_SCALE_SIZE(875), ELM_SCALE_SIZE(456) );
        evas_object_size_hint_max_set( m_pRectBottom, ELM_SCALE_SIZE(875), ELM_SCALE_SIZE(456) );
        evas_object_size_hint_weight_set( m_pRectBottom, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND );
        evas_object_size_hint_align_set( m_pRectBottom, EVAS_HINT_FILL, EVAS_HINT_FILL );
        evas_object_color_set( m_pRectBottom, 0, 0, 0, 10 );
        elm_table_pack( m_pTable, m_pRectBottom, 0, 1, 1, 1 );
        elm_table_pack( m_pTable, m_pList, 0, 1, 1, 1 );
	
        elm_object_content_set(m_pPopup, m_pTable);

        if ( m_pItemClass )
        {
            elm_genlist_item_class_free( m_pItemClass );
            m_pItemClass = NULL;
        }

        m_pItemClass = elm_genlist_item_class_new(); if(!m_pItemClass) return SF_STATUS_FAIL;
        m_pItemClass->item_style = "C_TextItem_WhiteSingleline05";
        m_pItemClass->func.text_get = GetGenlistItemStatus;
        m_pItemClass->func.content_get = NULL;
        m_pItemClass->func.state_get = NULL;
        m_pItemClass->func.del = NULL;
    } while ( FALSE );
    
    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::DestroyListViewObject()
{
    SF_LOG_I("Called;");

    if ( m_pItemClass != NULL ) 
    {
        elm_genlist_item_class_free(m_pItemClass);
        m_pItemClass = NULL;
    }
    
    if ( m_pList != NULL )
    {
        evas_object_del(m_pList);
        m_pList = NULL;
    }

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::ClearList()
{
    if ( m_pList != NULL )
    {
        elm_genlist_clear(m_pList);
    }    
}


/*
****************************************************************************************************
*
****************************************************************************************************
*/
char* SfBlockedListWindow::GetGenlistItemStatus( void* data, Evas_Object* obj, const char* part )
{
    char buf[1024]={'\0'};
    if ( data != NULL && part != NULL)
    {
        ListViewItem* pItem = static_cast< ListViewItem* >( data );
        if ( pItem != NULL && !strcmp(part, "elm.text.sliding"))
        {
            return strdup(pItem->path.c_str());
        }
		else if ( pItem != NULL && !strcmp(part, "elm.text"))
        {   
            return strdup(pItem->path.c_str());
        }
    }

    return strdup(buf);
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SelectItemCallback( void* data, Evas_Object* obj, void* event_info )
{
    //event_info = event_info;
    if ( data != NULL )
    {
        ListViewItem* pItem = (ListViewItem*)data;
        if ( pItem != NULL )
        {
            pItem->status = !pItem->status;
            elm_check_state_set( pItem->pCheckBox, (pItem->status) ? EINA_TRUE : EINA_FALSE);
        }
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::UpdateControlStatus()
{
    if ( m_pList != NULL)
    {
        const size_t c_itemsCount = elm_genlist_items_count(m_pList);
        if( c_itemsCount != 0 )
        {
            elm_object_focus_allow_set( m_pList, EINA_TRUE );
        }
        else
        {
            elm_object_focus_allow_set( m_pList, EINA_FALSE );
        }
        SF_LOG_I( "item count:%zu;", c_itemsCount ); 
    }
    if (m_pCloseButton != NULL)
    {
        elm_object_focus_set(m_pCloseButton, EINA_TRUE);  
    }
    return SF_STATUS_OK;
}
/*
****************************************************************************************************
*
****************************************************************************************************
*/
char* SfBlockedListWindow::TtsInfoCb(void* data, Evas_Object* obj)
{
    char *ret = NULL;
    SfBlockedListWindow *pthis = static_cast<SfBlockedListWindow*>(data);
    Eina_Strbuf *buf = eina_strbuf_new();
    
    if(bIsFirstSelect == TRUE)
    {
        eina_strbuf_append_printf(buf, "%s, %s", pthis->m_TTS_String.c_str(), elm_object_text_get(obj)); 
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
SF_STATUS SfBlockedListWindow::UpdateTtsText()
{
    if (m_pCloseButton == NULL)
    {
        return SF_STATUS_FAIL;
    }
    else
    {
        const Uint32 c_bufSize = 1024;
        char szMessage[ c_bufSize ] = {0};
        std::string strText;
        std::string strNumber;

        strText = dgettext(SF_CONTROLLER_PACKAGE, _("TV_SID_MIX_BLOCKED_ITEMS"));
        strNumber = SfStringUtils::NumberToString(m_blockedList.size());
        ReplaceString(strText, "<<A>>", strNumber);
        int ret = snprintf(szMessage, c_bufSize, "%s", strText.c_str());
        if ( ret < 0 || ret >= (int)c_bufSize)
        {
            SF_LOG_E( "snprintf() failed;" );
            return SF_STATUS_FAIL;
        }

        m_TTS_String = _("TV_SID_MONITORING_RESULTS");
        m_TTS_String +=  ".";
        m_TTS_String += std::string(szMessage);
        m_TTS_String +=  ".";
	bIsFirstSelect = TRUE;
        elm_access_info_cb_set(m_pCloseButton, ELM_ACCESS_INFO, TtsInfoCb, this);
    }
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_WINDOW_STATE SfBlockedListWindow::GetWindowState() const
{
    return m_windowState;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SetWindowState(SF_WINDOW_STATE state)
{
    m_windowState = state;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
const std::string& SfBlockedListWindow::GetWindowName() const
{
    return m_windowName;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SetWindowName(std::string windowName)
{
    m_windowName = windowName;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
Bool SfBlockedListWindow::IsHidden() const
{
    return m_isHidden;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SetHidden(Bool isHidden)
{
    m_isHidden = isHidden;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SetFromKernel(Bool isFromKernel)
{
    if (isFromKernel == FALSE)
    {
        if (m_AlreadyEntered == FALSE)
        {
            m_AlreadyEntered = TRUE;
        }
    }
    else
    {
        m_isFromKernel = isFromKernel;
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfBlockedListWindow::CreateWindowObject(const char* Title, const char* BodyText, const char* PopupStyle)
{
    const Uint32 c_bufSize = 1024;
    char szMessage[ c_bufSize ] = {0};
    SF_STATUS result = SF_STATUS_OK;
    do
    {
        /**
        * @brief Set window object as root obejct
        */
        m_pWindow = elm_win_add(NULL, m_windowName.c_str(), ELM_WIN_BASIC);
        if ( m_pWindow == NULL )
        {
            result = SF_STATUS_FAIL;
            break;
        }
        elm_win_title_set(m_pWindow, m_windowName.c_str());
        elm_win_autodel_set(m_pWindow, EINA_TRUE);
        elm_win_alpha_set( m_pWindow, EINA_TRUE );
        elm_win_focus_highlight_style_set(m_pWindow, NULL);
        elm_win_focus_highlight_enabled_set(m_pWindow, EINA_TRUE);
        elm_win_aux_hint_add(m_pWindow, "wm.policy.win.need.dim", "1");

        int rots[] = { 0, 90, 180, 270 };
        elm_win_wm_rotation_available_rotations_set(m_pWindow, rots, (sizeof(rots) / sizeof(int)));
        SF_LOG_I("add smart callback");
        evas_object_smart_callback_add( m_pWindow, c_windowCallbackInfo, SfWindowQuitHandler, NULL );
        evas_object_smart_callback_add( m_pWindow, c_windowRotCallbackInfo, SfWindowRotHandler, this); 
	
        m_pBox = elm_box_add(m_pWindow);
        evas_object_size_hint_weight_set(m_pBox, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        elm_win_resize_object_add(m_pWindow, m_pBox);
	
        m_pPopup = elm_popup_add(m_pBox);
        if ( m_pPopup == NULL )
        {
            result = SF_STATUS_FAIL;
            break;
        }
        
        if ( PopupStyle != NULL )
        {
            elm_object_style_set(m_pPopup, PopupStyle);
        }
        
        if ( Title != NULL )
        {
            elm_object_part_text_set(m_pPopup, "title,text", Title  );
        }
        evas_object_smart_callback_add( m_pPopup, "block,clicked", BlockClickedEventCb, this );
        m_pTouchEvent = ecore_event_handler_add( ECORE_EVENT_MOUSE_BUTTON_DOWN, TouchEventCb, this );
        ea_apply_color_pick(m_pPopup);

        // creating table object
        m_pTable = elm_table_add(m_pPopup);
        if (m_pTable == NULL)
        {
            result = SF_STATUS_FAIL;
            break;
        }

        if ( BodyText != NULL )
        {
            // Rectangle for containing LabelBox
            m_pRectTop = evas_object_rectangle_add( evas_object_evas_get(m_pPopup) );
            evas_object_size_hint_min_set( m_pRectTop, ELM_SCALE_SIZE(880), ELM_SCALE_SIZE(144) );
            evas_object_size_hint_weight_set( m_pRectTop, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND );
            evas_object_size_hint_align_set( m_pRectTop, EVAS_HINT_FILL, EVAS_HINT_FILL );

	    // making a Label
            m_pBodyLabel = elm_label_add( m_pPopup );
            if (m_pBodyLabel == NULL)
            {
                SF_LOG_E( "creating label is failed.;" );
                result = SF_STATUS_FAIL;
                break;
            }
            std::string strText;
            std::string strNumber;

            evas_object_size_hint_weight_set( m_pBodyLabel, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND );
            evas_object_size_hint_align_set( m_pBodyLabel, EVAS_HINT_FILL, EVAS_HINT_FILL );
            elm_label_line_wrap_set(m_pBodyLabel, ELM_WRAP_MIXED);
            elm_object_style_set(m_pBodyLabel, "popup/C_PopupBasic_WhiteRightLarge");
            elm_object_focus_allow_set(m_pBodyLabel, EINA_FALSE);
            strText = dgettext(SF_CONTROLLER_PACKAGE, BodyText);
            strNumber = SfStringUtils::NumberToString(m_blockedList.size());
            SF_LOG_I("%s:%s;", strText.c_str(), strNumber.c_str());
            ReplaceString(strText, "<<A>>", strNumber);
            if(m_oMode == UA_LTR_UI_ORIENTATION)
                snprintf(szMessage, c_bufSize, "<align=left>%s</align>", strText.c_str());
            else
                snprintf(szMessage, c_bufSize, "<align=right>%s</align>", strText.c_str());
            elm_object_text_set(m_pBodyLabel, szMessage);
	    
            elm_table_pack( m_pTable, m_pRectTop, 0, 0, 1, 1 );
            elm_table_pack( m_pTable, m_pBodyLabel, 0, 0, 1, 1 );
        } 

        /**
        * @brief Set handler to the window destroy event
        * @warning This is void function. Be careful with parameters you pass them
        */

        result = SF_STATUS_OK;
    } while ( FALSE );
    
    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::DestroyWindowObject()
{
    if (m_pBodyLabel)
    {
        evas_object_del(m_pBodyLabel);
        m_pBodyLabel = NULL;
    }
    
    if(m_pRectBottom)
    {
        evas_object_del(m_pRectBottom);
        m_pRectBottom = NULL;
    }
    
    if(m_pRectTop)
    {
        evas_object_del(m_pRectTop);
        m_pRectTop = NULL;
    }

    if (m_pTable)
    {
        evas_object_del(m_pTable);
        m_pTable = NULL;
    }
    
    if ( m_pPopup != NULL )
    {
        evas_object_smart_callback_del( m_pPopup, "block,clicked", BlockClickedEventCb );
        ecore_event_handler_del( m_pTouchEvent );
        evas_object_del(m_pPopup);
        m_pPopup = NULL;        
    }
    
    if ( m_pBox != NULL )
    {        
        evas_object_del(m_pBox);
        m_pBox = NULL;        
    }  
            
    if ( m_pWindow != NULL )
    {
        evas_object_smart_callback_del( m_pWindow, c_windowCallbackInfo, SfWindowQuitHandler );
        evas_object_smart_callback_del( m_pWindow, c_windowRotCallbackInfo, SfWindowRotHandler );
        SF_LOG_I("del smart callback;");
        
        evas_object_del(m_pWindow);
        m_pWindow = NULL;        
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SfWindowQuitHandler(void* pData, Evas_Object* pObject, void* pEvent)
{
    SF_LOG_I("%s;", static_cast<SfBlockedListWindow*> (pData)->GetWindowName().c_str());
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfBlockedListWindow::SfWindowRotHandler(void* pData, Evas_Object* pObject, void* pEvent)
{
    SfBlockedListWindow* pHandle = static_cast<SfBlockedListWindow*> (pData);

    int lfd_rotate_status = 0;
    int current_degree    = 0;

    vconf_get_int(VCONF_DISPLAY_ORIENTATION, &lfd_rotate_status);
    
    current_degree = elm_win_rotation_get(pObject);

    if (current_degree != 0)
    {
        elm_object_scale_set(pObject, 0.5625);

        evas_object_size_hint_min_set( pHandle->m_pList, SF_ELM_SCALE_SIZE(875, 1.125), SF_ELM_SCALE_SIZE(456, 1.125) );
        evas_object_size_hint_max_set( pHandle->m_pList, SF_ELM_SCALE_SIZE(875, 1.125), SF_ELM_SCALE_SIZE(456, 1.125) );

        evas_object_size_hint_min_set( pHandle->m_pRectTop, SF_ELM_SCALE_SIZE(875, 1.125), SF_ELM_SCALE_SIZE(144, 1.125) );
        evas_object_size_hint_max_set( pHandle->m_pRectTop, SF_ELM_SCALE_SIZE(875, 1.125), SF_ELM_SCALE_SIZE(144, 1.125) );

        evas_object_size_hint_min_set( pHandle->m_pRectBottom, SF_ELM_SCALE_SIZE(875, 1.125), SF_ELM_SCALE_SIZE(456, 1.125) );
        evas_object_size_hint_max_set( pHandle->m_pRectBottom, SF_ELM_SCALE_SIZE(875, 1.125), SF_ELM_SCALE_SIZE(456, 1.125) );

        if (lfd_rotate_status != 0)
        {
            elm_object_style_set(pObject, "portrait");
        }
    }
    else
    {
        elm_object_scale_set(pObject, 1.0);
        elm_object_style_set(pObject, "default");

        evas_object_size_hint_min_set( pHandle->m_pList, SF_ELM_SCALE_SIZE(875, 2.0), SF_ELM_SCALE_SIZE(456, 2.0) );
        evas_object_size_hint_max_set( pHandle->m_pList, SF_ELM_SCALE_SIZE(875, 2.0), SF_ELM_SCALE_SIZE(456, 2.0) );

        evas_object_size_hint_min_set( pHandle->m_pRectTop, SF_ELM_SCALE_SIZE(875, 2.0), SF_ELM_SCALE_SIZE(144, 2.0) );
        evas_object_size_hint_max_set( pHandle->m_pRectTop, SF_ELM_SCALE_SIZE(875, 2.0), SF_ELM_SCALE_SIZE(144, 2.0) );

        evas_object_size_hint_min_set( pHandle->m_pRectBottom, SF_ELM_SCALE_SIZE(875, 2.0), SF_ELM_SCALE_SIZE(456, 2.0) );
        evas_object_size_hint_max_set( pHandle->m_pRectBottom, SF_ELM_SCALE_SIZE(875, 2.0), SF_ELM_SCALE_SIZE(456, 2.0) );
    }
}


