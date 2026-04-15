/**
****************************************************************************************************
* @file SfBlockedListWindow.h
* @brief Security framework [SF] Blocked list window class declaration
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created Aug 29, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_BLOCKED_LIST_WINDOW_H_
#define _SF_BLOCKED_LIST_WINDOW_H_

#include "SfCommon.h"
#include "SfMessageBox.h"
#include "libprimitive/SfFs.h"
#include "libprovider/SfSettings.h"

#include <vector>
#include <string>

#include <uifw_misc.h>

/**
****************************************************************************************************
* @class SfBlockedListWindow
****************************************************************************************************
*/
class SfBlockedListWindow
{
public:
    /**
    ************************************************************************************************
    * @brief Blocked window class contructor
    ************************************************************************************************
    */
    SfBlockedListWindow( const std::string& windowName );

    /**
    ************************************************************************************************
    * @brief Destructor
    ************************************************************************************************
    */
    ~SfBlockedListWindow();

    /**
    ************************************************************************************************
    * @brief Interface function for window creation
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */
    SF_STATUS Create();
    
    /**
    ************************************************************************************************
    * @brief Interface functino for window destroying
    * @return SF_STATUS_OK
    ************************************************************************************************
    */
    SF_STATUS Destroy();
    
    /**
    ************************************************************************************************
    * @brief Show window object to the screen
    * @return SF_STATUS_OK
    ************************************************************************************************
    */
    SF_STATUS Show();

    /**
    ************************************************************************************************
    * @brief Hide window object from the screen
    * @return SF_STATUS_OK
    ************************************************************************************************
    */
    SF_STATUS Hide();

    /**
    ************************************************************************************************
    * @brief Get the window state
    * @return state of window SF_WINDOW_STATE
    ************************************************************************************************
    */
    SF_WINDOW_STATE GetWindowState() const;

    /**
    ************************************************************************************************
    * @brief Get the window state
    ************************************************************************************************
    */
    void SetWindowState(SF_WINDOW_STATE state);
    
    /**
    ************************************************************************************************
    * @brief Get the window name
    * @return Constant std::string object reference to the name of window
    ************************************************************************************************
    */
    const std::string& GetWindowName() const;

    /**
    ************************************************************************************************
    * @brief Set the window name
    ************************************************************************************************
    */
    void SetWindowName(std::string windowName);

    /**
    ************************************************************************************************
    * @brief check window state (showed/hiden)
    * @return TRUE if hiden and FALSE otherwise
    ************************************************************************************************
    */
    Bool IsHidden() const;
    
    /**
    ************************************************************************************************
    * @brief Set window state (showed/hiden)
    ************************************************************************************************
    */
    void SetHidden(Bool isHidden);

	/**
    ************************************************************************************************
    * @brief Set whether the message caomes from kernel
    ************************************************************************************************
    */
    static void SetFromKernel(Bool isFromKernel);
    
private:
    /**
    ************************************************************************************************
    * @brief callback function for elm_access_info_cb_set()
    * @param [in] data sended by caller.
    * @param [in] The object that callback is to be registered.
    * @return return value of eina_strbuf_string_steal();
    ************************************************************************************************
    */
    static char *TtsInfoCb(void* data, Evas_Object* obj);

    /**
    ************************************************************************************************
    * @brief Interface function for close button creation
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */    
    SF_STATUS CreateCloseButtonObject();
    
    /**
    ************************************************************************************************
    * @brief Interface function for close button destroying
    * @return SF_STATUS_OK
    ************************************************************************************************
    */    
    SF_STATUS DestroyCloseButtonObject();
    
    /**
    ************************************************************************************************
    * @typedef SfButtonCloseHandler
    * @brief Function type for close button handler
    * @param [in] pData User defined data that will be passed to handler function
    * @param [in] pObject Pointer to the object that raised event
    * @param [in] pEvent Pointer to the event
    * @return void
    ************************************************************************************************
    */   
    static void SfButtonCloseHandler(void* pData, Evas_Object* pObject, void* pEvent);

    /**
    ************************************************************************************************
    * @brief Interface function for list view creation
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */    
    SF_STATUS CreateListViewObject();
    
    /**
    ************************************************************************************************
    * @brief Interface function for list view destroying
    * @return SF_STATUS_OK
    ************************************************************************************************
    */        
    SF_STATUS DestroyListViewObject();
    
    /**
    ****************************************************************************************************
    * @brief Get the item label from the genlist 
    * @param [in] Pointer to ListViewItem 
    * @param [in] Pointer to evas object handle
    * @return item label
    ****************************************************************************************************
    */
    static char* GetGenlistItemStatus( void* data, Evas_Object* obj, const char* part );    

    /**
    ************************************************************************************************
    * @typedef SelectItemCallback
    * @brief Callback function type for list item select event.
    * @param [in] pData User defined data that will be passed to handler function
    * @param [in] pObject Pointer to the object that raised event
    * @param [in] pEvent Pointer to the event
    * @return void
    ************************************************************************************************
    */ 
    static void SelectItemCallback( void* data, Evas_Object* obj, void* event_info );
    
    /**
    ************************************************************************************************
    * @typedef SetContent
    * @brief Set list item cotent
    * @param [in] SfFilesList file list to adding on list
    * @return SF_STATUS_OK
    ************************************************************************************************
    */ 
    SF_STATUS SetContent( const SfFilesList& content );  
    
    /**
    ************************************************************************************************
    * @typedef ClearList
    * @brief clears all items in the list,
    * @return void
    ************************************************************************************************
    */ 
    void ClearList();

    /**
    ************************************************************************************************
    * @typedef RefreshItems
    * @brief refresh item in the list
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */ 
    SF_STATUS RefreshItems();

    /**
    ************************************************************************************************
    * @typedef RefreshAllData
    * @brief refresh list item & label
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */ 
    SF_STATUS RefreshAllData();

    /**
    ************************************************************************************************
    * @brief Create and initialize window object
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */
    SF_STATUS CreateWindowObject( const char* Title, const char* BodyText, const char* PopupStyle );
    
    /**
    ************************************************************************************************
    * @brief destroy and uninitialize window object
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */  
    void DestroyWindowObject();
    
    /**
    ************************************************************************************************
    * @brief Callback function that called when window is destroying
    * @param [in] pData Pointer to the user defined data
    * @param [in] pObject Pointer to the EVAS object
    * @param [in] pEvent pointer to the event was raised during window closing
    * @return void
    ************************************************************************************************
    */
    static void SfWindowQuitHandler(void* pData, Evas_Object* pObject, void* pEvent);

    /**
    ************************************************************************************************
    * @brief Callback function that called when window is destroying
    * @param [in] pData Pointer to the user defined data
    * @param [in] pObject Pointer to the EVAS object
    * @param [in] pEvent pointer to the event was raised during window closing
    * @return void
    ************************************************************************************************
    */
    static void SfWindowRotHandler(void* pData, Evas_Object* pObject, void* pEvent);

    /**
    ************************************************************************************************
    * @brief Callback function that called when return button is up
    * @return void
    ************************************************************************************************
    */
    static void KeyEventCb(void* pData, Evas* pEvas, Evas_Object* pEvasObj, void* pEvasEvent);

    /**
    ************************************************************************************************
    * @brief Callback function that called when user touch outside of popup
    * @return void
    ************************************************************************************************
    */
    static Eina_Bool TouchEventCb( void* data, int type, void* event );

    /**
    ************************************************************************************************
    * @brief Callback function that called when user touch outside of popup
    * @return void
    ************************************************************************************************
    */
    static void BlockClickedEventCb( void* pData, Evas_Object* pEvasObj, void* pEvasEvent );

    /**
    ************************************************************************************************
    * @brief update status of Window controls 
    * @return SF_STATUS_OK
    ************************************************************************************************
    */
    SF_STATUS UpdateControlStatus();

    /**
    ************************************************************************************************
    * @brief update Text for TTS 
    * @return SF_STATUS_OK
    ************************************************************************************************
    */
    SF_STATUS UpdateTtsText();
    
private:    
    std::string m_windowName;       ///< Window name
    std::string m_showMenuTitle;    ///< Window title
    std::string m_TTS_String;

    SF_WINDOW_STATE m_windowState;  ///< Window state
    Bool m_isHidden;
    static Bool m_isFromKernel;
    static Bool m_AlreadyShowFromKernel;
    static Bool m_AlreadyEntered;
    Ua_Orientation_Mode m_oMode;
    
    Evas_Object* m_pWindow;         ///< Window object
    Evas_Object* m_pBox;
    Evas_Object* m_pPopup;          ///< Popup object
    Evas_Object* m_pTable;            ///< Box object
    Evas_Object* m_pRectTop;
    Evas_Object* m_pRectBottom;
    Evas_Object* m_pBodyLabel;     ///< Label object

    /**
    ************************************************************************************************
    * @brief Button 'close' object
    ************************************************************************************************
    */
    Evas_Object* m_pCloseButton;

    /**
    ************************************************************************************************
    * @brief List view graphic object
    ************************************************************************************************
    */
    Evas_Object* m_pList;
    
    /**
    ************************************************************************************************
    * @brief genlist item class in a given genlist widget
    ************************************************************************************************
    */
    Elm_Genlist_Item_Class* m_pItemClass;

    /**
    ************************************************************************************************
    * @brief Content to show in list view
    ************************************************************************************************
    */
    ListViewItemVector  m_items;

    /**
    ************************************************************************************************
    * @brief Content to show in list view
    ************************************************************************************************
    */
    SfFilesList m_blockedList;
    Ecore_Event_Handler*  m_pTouchEvent;
public:
    SF_WINDOW_TYPE   m_ListWindowType;
};

#endif  /* _SF_BLOCKED_LIST_WINDOW_H_ */
