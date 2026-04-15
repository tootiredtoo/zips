/**
****************************************************************************************************
* @file SfReporterWindow.h
* @brief Security framework [SF] Reporter UI from Other Security Components
* @author Namgwon Lee (namgwon.lee@samsung.com)
* @date Created JUNE 1, 2016 09:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2016. All rights reserved.
****************************************************************************************************/
#ifndef _SF_REPORTER_WINDOW_H
#define _SF_REPORTER_WINDOW_H

#include "SfCommon.h"
#include "SfMessageBox.h"
#include "libprimitive/UnixSocket.h"
#include "common/SfPushNotification.h"

#include <jsoncpp/json/json.h>

class SfReporterWindow
{
public:
    SfReporterWindow();
    ~SfReporterWindow();

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
    ****************************************************************************************************
    * @brief                         CreateReportMessageBox
    * @param [in] SfMessageBox       Message Box Object
    * @param [in] ReportWindowInfo   ReportWindow Information
    * @return                        SF_STATUS_OK if Sucess, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS CreateReportMessageBox( SfMessageBox* pMsgBox, MsgBoxInfo Info );

     /**
    ****************************************************************************************************
    * @brief                 Destroy given message box
    * @param [in] Messagebox instance
    * @return                SF_STATUS_OK if Sucess, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS DestroyMsgBox(SfMessageBox* pMsgBox);

    /**
    ****************************************************************************************************
    * @brief                    ShowReportMessageBox
    * @param [in] SfMessageBox  Message Box Object
    * @param [in] Message       Message Box String
    * @return                   SF_STATUS_OK if Sucess, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS ShowReportMessageBox(SfMessageBox* pMsgBox, std::string Message);

    /**
    ****************************************************************************************************
    * @brief                	GetReportWindowInfo
    * @param [in]  bundlevalue  Json String
    * @param [out] MsgBoxInfo   Message Box Information
    * @return                   SF_STATUS_OK if Sucess, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    SF_STATUS GetReportWindowInfo(const char* bundlevalue, MsgBoxInfo& Info );
	
    /**
    ****************************************************************************************************
    * @brief                	Send request messagebox or Nofication is closed.
    * @param [in]  HostName    	Host Name
    * @param [in]  Action       Request action
    * @return                   SF_STATUS_OK if Sucess, SF_STATUS_FAIL otherwise
    ****************************************************************************************************
    */
    static SF_STATUS SendClickedMessage( const char* HostName, const char* Action );

private:

    /**
    ****************************************************************************************************
    * @brief Callback for ok button on message box click
    * @param [in] Messagebox callback parameter
    ****************************************************************************************************
    */    
    static void OkButtonCb(MessageBoxButtonCbParam* pData);

    /**
    ****************************************************************************************************
    * @brief Callback for yes button no message box click
    * @param [in] Messagebox callback parameter
    ****************************************************************************************************
    */  
    static void AutoReportButtonCb(MessageBoxButtonCbParam* pData);

    /**
    ****************************************************************************************************
    * @brief Callback for yes button no message box click
    * @param [in] Messagebox callback parameter
    ****************************************************************************************************
    */  
    static void ReportOnceButtonCb(MessageBoxButtonCbParam* pData);
	
public:
    std::string Agreementmessage;
};
#endif /*_SF_REPORTER_WINDOW_H*/