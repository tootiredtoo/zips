/**
****************************************************************************************************
* @file SfMessageBox.h
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
#ifndef _SF_MESSAGE_BOX_H_
#define _SF_MESSAGE_BOX_H_

#include "SfCommon.h"
#include "SfEflIncludes.h"
#include "libcore/SfCore.h"
#include "libprimitive/UnixSocket.h"

#include <jsoncpp/json/json.h>
#include <string>


typedef void (*MsgBoxBtnCallback)( MessageBoxButtonCbParam* pData );

enum MessageBoxType
{
    MSG_BOX_TITLE_OK                    = 0, // Message Box(Ok) with Title bar.
    MSG_BOX_TITLE_YES_NO                = 1, // Message Box(Yes-No) with Title bar.
    MSG_BOX_NO_TITLE_OK                 = 2, // Message Box(Ok) without Title bar.
    MSG_BOX_NO_TITLE_YES_NO             = 3, // Message Box(Yes-No) without Title bar and default button is NO.
    MSG_BOX_NO_TITLE_YES_NO_DEFAULT_YES = 4, // // Message Box(Yes-No) without Title bar and default button is Yes.
    MSG_BOX_TITLE_REPORT_NOTIFICATION   = 5,
    MSG_BOX_NO_TITLE_YES_NO_REPORTER    = 6,
    MSG_BOX_NO_TITLE_OK_REPORTER        = 7
};

enum DimNeededType
{
    SF_DIM_INIT = 0, 
    SF_DIM_ISOLATED_LIST,
    SF_DIM_MAX
};

enum MsgBoxRetType
{
    SF_DEFAULT = 0,
    SF_CLICK_BTN_1,
    SF_CLICK_BTN_2
};

typedef struct
{
    MessageBoxType MsgType;
    std::string MsgTitle;
    std::string MsgMessage;
    std::string MsgData;
} MsgBoxInfo;

class SfMessageBox
{
private:    // type
    struct BtnCallbackInfo
    {
        MsgBoxBtnCallback   cb;
        void*               param;

        BtnCallbackInfo()
            : cb( NULL )
            , param( NULL )
        {
        }
    };
public:     // func
    /**
    ****************************************************************************************************
    * @brief Constructor
    ****************************************************************************************************
    */
    SfMessageBox( MessageBoxType type );

    /**
    ****************************************************************************************************
    * @brief Destructor
    ****************************************************************************************************
    */
    ~SfMessageBox();
    
    /**
    ****************************************************************************************************
    * @brief Register ok button callback
    * @param [in] Callback function
    * @param [in] Context
    * @param [in] Additional user parameter
    * @return void
    ****************************************************************************************************
    */
    void SetButton1Callback( MsgBoxBtnCallback cb, void* pContext, void* pParam = NULL);
    
    /**
    ****************************************************************************************************
    * @brief Register yes button callback
    * @param [in] Callback function
    * @param [in] Context
    * @param [in] Additional user parameter
    * @return void
    ****************************************************************************************************
    */
    void SetButton2Callback( MsgBoxBtnCallback cb, void* pContext, void* pParam = NULL);
    
    /**
    ****************************************************************************************************
    * @brief Register no button callback
    * @param [in] Callback function
    * @param [in] Context
    * @param [in] Additional user parameter
    * @return void
    ****************************************************************************************************
    */
    void SetButton3Callback( MsgBoxBtnCallback cb, void* pContext, void* pParam = NULL);

    /**
    ****************************************************************************************************
    * write something
    ****************************************************************************************************
    */
    void RefreshMessageLable( const char* message);

    /**
    ****************************************************************************************************
    * @brief Create the objects displayed in the messagebox and set the data to display.
    * @param void
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS Create(const char* title, MsgBoxRetType retType = SF_DEFAULT);

    SF_STATUS Create(const char* title, DimNeededType type, void* pObject, MsgBoxRetType retType = SF_DEFAULT);
    
    /**
    ****************************************************************************************************
    * @brief Show objects in the messagebox
    * @param void
    * @return SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS Show(const char* message, Int timeOut = 0 );

    /**
    ****************************************************************************************************
    * @brief Destroy objects in the messagebox
    * @param void
    * @return SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS Destroy();
    
    /**
    ****************************************************************************************************
    * @brief Hide objects in the messagebox
    * @param void
    * @return SF_STATUS_OK
    ****************************************************************************************************
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
    * @brief Set the window state
    ************************************************************************************************
    */
    void SetWindowState(SF_WINDOW_STATE state);

    /**
    ************************************************************************************************
    * @brief check window state (showed/hidden)
    * @return TRUE if hiden and FALSE otherwise
    ************************************************************************************************
    */
    Bool IsHidden() const;
    
    /**
    ****************************************************************************************************
    * @brief Set window state (showd/hidden)
    * @param [in] Window state
    ****************************************************************************************************
    */
    void SetHidden(Bool isHidden);
    
    /**
    ****************************************************************************************************
    * @brief Call the registered callback when button1 clicked
    ****************************************************************************************************
    */
    void CallButton1Cb();
    
    /**
    ****************************************************************************************************
    * @brief Call the registered callback when button2 clicked
    ****************************************************************************************************
    */
    void CallButton2Cb();
    
    /**
    ****************************************************************************************************
    * @brief Call the registered callback when button3 clicked
    ****************************************************************************************************
    */
    void CallButton3Cb();
private:    // func
    /**
    ************************************************************************************************
    * @brief callback function for elm_access_info_cb_set()
    * @param [in] data sended by caller.
    * @param [in] The object that callback is to be registered.
    * @return return value of eina_strbuf_string_steal();
    ************************************************************************************************
    */    
    static char *TtsInfoCallback(void* data, Evas_Object *obj);
    
    /**
    ****************************************************************************************************
    * @brief Add ok button in the messagebox and add button callback
    * @param void
    * @return SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS SetupWithoutTitleOk( const char* message );
    
    /**
    ****************************************************************************************************
    * @brief Add yes/no button in the messagebox and add button callbacks
    * @return SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS SetupWithoutTitleYesNo( const char* message );
    /**
    ****************************************************************************************************
    * @brief Add 3 buttons in the messagebox and add button callbacks
    * @return SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS SetupTitleReport( const char* message );

    /**
    ****************************************************************************************************
    * @brief                    Title
    * @param [in]  xx           param notes
    * @param [out] xx           param notes
    * @return                   TRUE if note, FALSE otherwise
    ****************************************************************************************************
    */
    void AddButton( Evas_Object* pButtonObj, Evas_Object* pImageObj, std::string ButtonIndex,
                    const char* ButtonName, const char* message, const char* ButtonIcon, Evas_Smart_Cb func );
    /**
    ****************************************************************************************************
    * @brief                    Title
    * @param [in]  xx           param notes
    * @param [out] xx           param notes
    * @return                   TRUE if note, FALSE otherwise
    ****************************************************************************************************
    */
    void DeleteButton( Evas_Object* pButtonObj, Evas_Object* pImageObj, Evas_Smart_Cb func );

    /**
    ****************************************************************************************************
    * @brief Callback for the keyup event
    * @param [in] Messagebox instance
    * @param [in] Pointer to evas canvas handle
    * @param [in] Pointer to evas object handle
    * @param [in] Pointer to evas event handle
    * @return void
    ****************************************************************************************************
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
    * @brief Callback function that called when window is destroying
    * @param [in] pData Pointer to the user defined data
    * @param [in] pObject Pointer to the EVAS object
    * @param [in] pEvent pointer to the event was raised during window closing
    * @return void
    ************************************************************************************************
    */
    static void SfWindowRotHandler(void* pData, Evas_Object* pObject, void* pEvent);
    
    /**
    ****************************************************************************************************
    * @brief Callback for ok button clicked event
    * @param [in] Messagebox instance
    * @param [in] Pointer to evas object handle
    * @param [in] Pointer to evas event handle
    * @return void
    ****************************************************************************************************
    */
    static void Button1Cb(void* pData, Evas_Object* pObject, void* pEvent);
    
    /**
    ****************************************************************************************************
    * @brief Callback for yes button clicked event
    * @param [in] Messagebox instance
    * @param [in] Pointer to evas object handle
    * @param [in] Pointer to evas event handle
    * @return void
    ****************************************************************************************************
    */
    static void Button2Cb(void* pData, Evas_Object* pObject, void* pEvent);

    /**
    ****************************************************************************************************
    * @brief Callback for no button clicked event
    * @param [in] Messagebox instance
    * @param [in] Pointer to evas object handle
    * @param [in] Pointer to evas event handle
    * @return void
    ****************************************************************************************************
    */
    static void Button3Cb(void* pData, Evas_Object* pObject, void* pEvent);

private:    // var
    std::string     m_windowName;           ///< Window name
    SF_WINDOW_STATE m_windowState;          ///< Window state        
    Bool            m_isHidden;             ///< Hidden state
    Bool            m_isNeedFree;
    
    Evas_Object*    m_pWindow;              ///< Window object   
    Evas_Object*    m_pBox;
    Evas_Object*    m_pPopup;                ///< Popup object
    Evas_Object*    m_pParentObject;

    Evas_Object*    m_pButton1;            ///< Pointer to button1 object
    Evas_Object*    m_pButton2;            ///< Pointer to button2 object
    Evas_Object*    m_pButton3;            ///< Pointer to no button object

    std::string     m_message;             ///< Message
    std::string     m_TTS_msg;
    std::string     m_alertMessage;        ///< Alert message
    Ecore_Timer*    m_timerHideMsgBox;     ///< Pointer to ecore timer  
    
    MsgBoxBtnCallback  m_cbButton1;        ///< Button1 callbck   
    MsgBoxBtnCallback  m_cbButton2;        ///< Button2 callbck   
    MsgBoxBtnCallback  m_cbButton3;        ///< Button3 callbck   
    
    MessageBoxButtonUserParam*   m_pParamButton1;
    MessageBoxButtonUserParam*   m_pParamButton2;
    MessageBoxButtonUserParam*   m_pParamButton3;  

    DimNeededType m_DimType;               ///< whether the dim is needed.
    Ecore_Event_Handler*  m_pTouchEvent;

public:
    MessageBoxType  m_type;         ///< Message box type
    MsgBoxRetType   m_retType;

    void SetNeedFree(Bool bNeed) { m_isNeedFree = bNeed; }
    Bool GetNeedFree(void) { return m_isNeedFree; }
};

#endif  // _SF_MESSAGE_BOX_H_
