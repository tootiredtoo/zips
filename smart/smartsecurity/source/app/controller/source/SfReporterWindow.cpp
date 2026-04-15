/**
****************************************************************************************************
* @file SfReporterWindow.cpp
* @brief Security framework [SF] Reporter UI from Other Security Components
* @author Namgwon Lee (namgwon.lee@samsung.com)
* @date Created JUNE 1, 2016 09:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2016. All rights reserved.
****************************************************************************************************/
#include "SfReporterWindow.h"
#include "common/SfTasksTags.h"
#include "libprovider/SfSettings.h"

#include <app.h>
#include <aul.h>
#include <vconf.h>
#include <bundle.h>
#include <bundle_internal.h>

#define UI_TIMEOUT 3600

static std::string AgreeMsg;
static std::vector< SfMessageBox* >   vMsgBox;
/**
****************************************************************************************************
* write something
****************************************************************************************************
*/
SfReporterWindow::SfReporterWindow()
{
}
/**
****************************************************************************************************
* write something
****************************************************************************************************
*/
SfReporterWindow::~SfReporterWindow()
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfReporterWindow::Create()
{
    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfReporterWindow::Destroy()
{
    for (int i = (vMsgBox.size()-1) ; i>=0 ; i-- )
    {
        SfMessageBox *pMsgBox = ((SfMessageBox*)vMsgBox[i]);
        if (pMsgBox != NULL)
        {
            pMsgBox->Destroy();   
            vMsgBox.erase (vMsgBox.begin() + i);
            SF_LOG_I("erase (left count:%zu)", vMsgBox.size());
            if (pMsgBox->m_type == MSG_BOX_TITLE_REPORT_NOTIFICATION)
            {
                SfReporterWindow::SendClickedMessage( c_daemonNameQueue, c_taskReportSendNo );
            }
            
            if (pMsgBox->GetNeedFree() == TRUE)
            {
                SF_DELETE pMsgBox;
            }
        }
    }
    return SF_STATUS_OK;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfReporterWindow::GetReportWindowInfo(const char* bundlevalue, MsgBoxInfo& Info )
{
    SF_LOG_I("Called;");
    Json::Value root;
    Json::Reader reader;
    try
    {
        if ( !reader.parse( bundlevalue, root, false ) )
        {
            SF_LOG_E( "Parse(%s) failed;", bundlevalue );
            return SF_STATUS_FAIL;
        }
        Info.MsgTitle   = root[ "title" ].asString();
        Info.MsgMessage = root[ "message" ].asString();
        Info.MsgData    = root[ "data" ].asString();
        Info.MsgType    = (MessageBoxType) root[ "type" ].asInt();
    }
    catch(Json::Exception& e)
    {
        SF_LOG_E("Exception from Json exception[%s];", e.what());
        return SF_STATUS_FAIL;
    } 
    return SF_STATUS_OK;

}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfReporterWindow::CreateReportMessageBox( SfMessageBox* pMsgBox, MsgBoxInfo Info  )
{
    SF_LOG_I("Called;");
    SF_STATUS status = SF_STATUS_OK;
    do
    {
        if (pMsgBox)
        {
            if ( SF_FAILED( pMsgBox->Create( Info.MsgTitle.c_str() )) )
            {
                SF_LOG_E("Can not create MessageBoxSuccess");
                status = SF_STATUS_FAIL;
                break;
            }

            if ( Info.MsgType == MSG_BOX_NO_TITLE_OK_REPORTER )
            {
                pMsgBox->SetButton1Callback( OkButtonCb, this, pMsgBox );
            }
            else if( Info.MsgType == MSG_BOX_TITLE_REPORT_NOTIFICATION )
            {
                // Agreementmessage = Info.MsgData;
                AgreeMsg = Info.MsgData;
                pMsgBox->SetButton1Callback( AutoReportButtonCb, this, pMsgBox );
                pMsgBox->SetButton2Callback( ReportOnceButtonCb, this, pMsgBox );
                pMsgBox->SetButton3Callback( OkButtonCb, this, pMsgBox );
            }
            vMsgBox.push_back(pMsgBox);
        }
        else
        {
            SF_LOG_E("pMsgBox is NULL.");
            status = SF_STATUS_FAIL;
            break;
        }
    } while ( false );

    SF_LOG_I("vec size(%zu);", vMsgBox.size());
    
    if ( pMsgBox != NULL && SF_FAILED( status ) )
    {
        pMsgBox->Destroy();
        delete pMsgBox;
        pMsgBox = NULL;
        SF_LOG_I("Failed;");
    }
    
    return status;
}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfReporterWindow::DestroyMsgBox(SfMessageBox* pMsgBox)
{
    SF_LOG_I("size:%zu;",vMsgBox.size() );
    
    for (int i = (vMsgBox.size()-1) ; i>=0 ; i-- )
    {
        SF_LOG_I("[%p];", pMsgBox);
        SF_LOG_I("idx[%d]=%p", i, vMsgBox[i]);
        if ( (void*)vMsgBox[i] == (void*)pMsgBox )
        {
            vMsgBox.erase (vMsgBox.begin()+i);
            SF_LOG_I("Found(left:%zu);", vMsgBox.size()); 
            break;
        }
    }
    return SF_STATUS_OK;

}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfReporterWindow::ShowReportMessageBox( SfMessageBox* pMsgBox, std::string Message)
{
    SF_STATUS status = SF_STATUS_FAIL;
    
    if ( pMsgBox != NULL && !Message.empty() )
    {
        status = pMsgBox->Show(Message.c_str(), UI_TIMEOUT);
    }
    else
    {
        SF_LOG_E("Invalid messagebox parameters");
    }

    return status;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfReporterWindow::OkButtonCb(MessageBoxButtonCbParam* pData)
{
    SF_LOG_I( "Called;" );    

    if ( pData != NULL && pData->pUserParam != NULL )
    {
        SfReporterWindow* pReporter = static_cast<SfReporterWindow*> (pData->pUserParam->pContext);
        if ( pReporter != NULL )
        {
            SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData->pUserParam->pParam);
            pReporter->DestroyMsgBox(pMsgBox);
            SfReporterWindow::SendClickedMessage( c_daemonNameQueue, c_taskReportSendNo );
        }
    }        
    else
    {
        SF_LOG_E("Invalid parameters was passed;");
    }
}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfReporterWindow::AutoReportButtonCb(MessageBoxButtonCbParam* pData)
{
    SF_LOG_I( "Called;" );

    if ( pData != NULL && pData->pUserParam != NULL )
    {
        SfReporterWindow* pReporter = static_cast<SfReporterWindow*> (pData->pUserParam->pContext);
        if ( pReporter != NULL )
        {
            SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData->pUserParam->pParam);
            pReporter->DestroyMsgBox(pMsgBox);
            SfReporterWindow::SendClickedMessage( c_daemonNameQueue, c_taskReportSendAlways );
        }
    }        
    else
    {
        SF_LOG_E("Invalid parameters was passed;");
    }
}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
void SfReporterWindow::ReportOnceButtonCb(MessageBoxButtonCbParam* pData)
{
    SF_LOG_I( "Called;" );    

    if ( pData != NULL && pData->pUserParam != NULL )
    {
        SfReporterWindow* pReporter = static_cast<SfReporterWindow*> (pData->pUserParam->pContext);
        if ( pReporter != NULL )
        {
            SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData->pUserParam->pParam);
            pReporter->DestroyMsgBox(pMsgBox);
            SfReporterWindow::SendClickedMessage( c_daemonNameQueue, c_taskReportSendOnce );
        }
    }        
    else
    {
        SF_LOG_E("Invalid parameters was passed;");
    }
}

/**
****************************************************************************************************
* write something
****************************************************************************************************
*/
SF_STATUS SfReporterWindow::SendClickedMessage( const char* HostName, const char* Action )
{
    SF_LOG_I("\e[1;35mClick ;\e[0m");
    if ((HostName == NULL) || (Action == NULL))
    {        
        SF_LOG_E( "[invalid param];" );
        return SF_STATUS_FAIL;
    }
    
    UnixSocket socket;
    if (SF_FAILED(socket.ConnectToHostNonBlocking(HostName)))
    {
        SF_LOG_E( "Failed to connect to reporter;" );
        socket.Disconnect();
        return SF_STATUS_FAIL;
    }

    Json::Value root;
    Json::FastWriter fastwriter;
    root[ c_taskTagState ] = Action;

    std::string message = fastwriter.write( root );

    SF_LOG_I("\e[1;35mSend Msg: %s;\e[0m", message.c_str());

    if (!socket.SendString(message))
    {
        SF_LOG_E("Failed to send request [%s];", message.c_str());
        socket.Disconnect();
        return SF_STATUS_FAIL;
    }

    socket.Disconnect();
    return SF_STATUS_OK;
}