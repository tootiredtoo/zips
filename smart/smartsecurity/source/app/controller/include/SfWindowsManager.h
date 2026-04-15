/**
****************************************************************************************************
* @file SfWindowManager.h
* @brief Security framework [SF] window manager class declaration
****************************************************************************************************
*/

#ifndef _SF_WINDOWS_MANAGER_H_
#define _SF_WINDOWS_MANAGER_H_

#include "SfBlockedListWindow.h"
#include "SfReporterWindow.h"

/**
****************************************************************************************************
* @class SfWindowsManager
****************************************************************************************************
*/
class SfWindowsManager
{
public:
    /**
    ****************************************************************************************************
    * @brief Constructor
    ****************************************************************************************************
    */
    SfWindowsManager();
    
    /**
    ****************************************************************************************************
    * @brief Destructor
    ****************************************************************************************************
    */
    ~SfWindowsManager();
    
    /**
    ****************************************************************************************************
    * @brief Create windows
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS Create();
    
    /**
    ****************************************************************************************************
    * @brief Destroy windows
    * @return SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS Destroy();
    
    /**
    ****************************************************************************************************
    * @brief Switch window to show
    * @param [in] Window type selecet by user in System Menu
    * @param [in] Json string containing the message box information when the window type is message box
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS Dispatch(SF_WINDOW_TYPE window, char* args);
    
    /**
    ****************************************************************************************************
    * @brief Create blocked list window
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS CreateBlockedListWindow(Bool isFromKernel);
    
    /**
    ****************************************************************************************************
    * @brief Destroy blocked list window
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS DestroyBlockedListWindow();
    
    /**
    ****************************************************************************************************
    * @brief Show blocked list window
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS ShowBlockedListWindow(SF_WINDOW_TYPE Type);
    
    /**
    ****************************************************************************************************
    * @brief Create reporter window
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS CreateReporterWindow();
    
    /**
    ****************************************************************************************************
    * @brief Destroy reporter window
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS DestroyReporterWindow();  
    
    /**
    ****************************************************************************************************
    * @brief Create message box
    * @param [in] Messagebox type
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS CreateMsgBox( SfMessageBox* pMsgBox, MsgBoxInfo Info );

    /**
    ****************************************************************************************************
    * @brief Destroy given message box
    * @param [in] Messagebox instance
    * @return SF_STATUS_OK
    ****************************************************************************************************
    */
    SF_STATUS DestroyMsgBox(SfMessageBox* pMsgbox);

    /**
    ****************************************************************************************************
    * @brief Show the message box to display a given message
    * @param [in] Messagebox instance
    * @param [in] Message
    * @return SF_STATUS_OK on success SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS ShowMsgBox(SfMessageBox* pMsgBox, const char* message);

    /**
    ****************************************************************************************************
    * @brief Destroy all created message box
    ****************************************************************************************************
    */
    void DestroyAllMsgBox();

private:
  
    /**
    ****************************************************************************************************
    * @brief Callback for ok button on message box click
    * @param [in] Messagebox callback parameter
    ****************************************************************************************************
    */    
    static void MsgBoxOkButtonCb(MessageBoxButtonCbParam* pData);
    
    /**
    ****************************************************************************************************
    * @brief Callback for yes button on message box click
    * @param [in] Messagebox callback parameter
    ****************************************************************************************************
    */  
    static void MsgBoxYesButtonCb(MessageBoxButtonCbParam* pData);

    /**
    ****************************************************************************************************
    * @brief Callback for yes button no message box click
    * @param [in] Messagebox callback parameter
    ****************************************************************************************************
    */  
    static void MsgBoxNoButtonCb(MessageBoxButtonCbParam* pData);
    
    /**
    ****************************************************************************************************
    * @brief Parse the message box properties from json string
    * @param [in] bundlevalue string containing the message box information when the window type is message box
    * @param [out] Info Messagebox Information
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL on fail
    ****************************************************************************************************
    */
    SF_STATUS GetMsgWindowInfo( const char* bundlevalue, MsgBoxInfo& Info );

private:
    SfBlockedListWindow*    m_pBlockedListWindow;   ///< Pointer to blocked list window instance
    SfReporterWindow*       m_pReporterWindow;        ///< Pointer to reporter window instance
    std::vector< SfMessageBox* >   m_vMsgBox;       ///< Message box list
public:
    std::string     m_DataString;                       ///< string for report notifcation's string
    Bool            m_doDestroy;
};

#endif /* _SF_WINDOWS_MANAGER_H_ */
