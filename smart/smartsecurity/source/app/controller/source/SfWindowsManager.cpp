
// local
#include "SfApplication.h"
#include "SfWindowsManager.h"
#include "libcore/SfDebug.h"
#include "common/SfPushNotification.h"
#include "libprimitive/UnixSocket.h"
#include "common/SfTasksTags.h"

// system
#include <app.h>
#include <jsoncpp/json/json.h>
#include <unistd.h>
#include <uifw_misc.h>

SfWindowsManager::SfWindowsManager()
    : m_pBlockedListWindow ( NULL )
    , m_pReporterWindow ( NULL )
    , m_DataString ()
    , m_doDestroy ( TRUE )
{
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfWindowsManager::~SfWindowsManager()
{ 
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/

SF_STATUS SfWindowsManager::Create()
{
    SF_LOG_I("Called;");
    
    if ( m_pBlockedListWindow == NULL )
    {
        m_pBlockedListWindow = new SfBlockedListWindow("Blocked List");
    }

    if ( m_pReporterWindow == NULL )
    {
        m_pReporterWindow = new SfReporterWindow();
    }

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::Destroy()
{
    SF_LOG_I("Destroy");

    //message box clear?? - TODO::  Edit Code;
    DestroyAllMsgBox();

    DestroyBlockedListWindow();
    delete m_pBlockedListWindow;
    m_pBlockedListWindow = NULL;

    DestroyReporterWindow();
    delete m_pReporterWindow;
    m_pReporterWindow = NULL;
    
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
* 
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::Dispatch(SF_WINDOW_TYPE window, char* args)
{
    SF_LOG_I("Called;");
    SF_STATUS result = SF_STATUS_FAIL;
    switch(window)
    {
        case SF_WINDOW_TYPE_BLOCKED_LIST:
            {
                if ( CreateBlockedListWindow(FALSE) == SF_STATUS_OK )
                {
                    result = ShowBlockedListWindow( window );
                }
            }break;
        case SF_WINDOW_TYPE_BLOCKED_LIST_NOTI:
            {
                if ( CreateBlockedListWindow(TRUE) == SF_STATUS_OK )
                {
                    result = ShowBlockedListWindow( window );
                }
            }break;
        case SF_WINDOW_TYPE_MSGBOX:
            {
                SF_LOG_I("window : SF_WINDOW_TYPE_MSGBOX");
                MsgBoxInfo Info;
                if ( SF_SUCCESS ( GetMsgWindowInfo( args, Info )) )
                {
                    SfMessageBox* pMsgBox = SF_NEW SfMessageBox( Info.MsgType );
                    if (pMsgBox)
                    {
                        pMsgBox->SetNeedFree(TRUE);
                        if( SF_SUCCESS (CreateMsgBox( pMsgBox, Info)) )
                        {
                            m_DataString = Info.MsgData;
                            result = ShowMsgBox( pMsgBox, Info.MsgMessage.c_str());
                        } 
                    }
                }
            }break;
        case SF_WINDOW_TYPE_GLOBAL_NOTI:
            break;  
        case SF_WINDOW_TYPE_REPORT_NOTI:
            {
                MsgBoxInfo Info;
                std::string tempStr;

                if ( CreateReporterWindow() == SF_STATUS_OK )
                {
                    if( SF_SUCCESS ( m_pReporterWindow->GetReportWindowInfo( args, Info )) )
                    {
                        SfMessageBox* pMsgBox = SF_NEW SfMessageBox( Info.MsgType );
                        if (pMsgBox)
                        {
                            pMsgBox->SetNeedFree(TRUE);
                            if( SF_SUCCESS( m_pReporterWindow->CreateReportMessageBox( pMsgBox, Info )) )
                            {
                                tempStr = Info.MsgMessage + "</br>" + Info.MsgData;
                                m_pReporterWindow->ShowReportMessageBox( pMsgBox, tempStr );
                            }
                        }
                    }
                }
            }break;
        default:
            SF_LOG_I("Unknown window;");
            break;
    }
    
    return result;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::GetMsgWindowInfo( const char* bundlevalue, MsgBoxInfo& Info )
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
        Info.MsgType    = (MessageBoxType)root[ "type" ].asInt();
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
SF_STATUS SfWindowsManager::CreateMsgBox(SfMessageBox* pMsgBox, MsgBoxInfo Info)
{
    SF_LOG_I("Called;");

    SF_STATUS status = SF_STATUS_OK;

    do
    {
        if (pMsgBox == NULL)
        {
            SF_LOG_E("pMsgBox is NULL;");
            status = SF_STATUS_FAIL;
            break;
        }

        if ( SF_FAILED( pMsgBox->Create( Info.MsgTitle.c_str() )) )
        {
            SF_LOG_E("Can not create MessageBoxSuccess");
            status = SF_STATUS_FAIL;
            break;
        }

        if ( Info.MsgType == MSG_BOX_NO_TITLE_OK || Info.MsgType == MSG_BOX_TITLE_OK )
        {
            pMsgBox->SetButton1Callback( MsgBoxOkButtonCb, this, pMsgBox );
        }
        else if ( Info.MsgType == MSG_BOX_NO_TITLE_YES_NO || Info.MsgType == MSG_BOX_TITLE_YES_NO )
        {
            pMsgBox->SetButton1Callback( MsgBoxYesButtonCb, this, pMsgBox );
            pMsgBox->SetButton2Callback( MsgBoxNoButtonCb, this, pMsgBox );
        }       

        m_vMsgBox.push_back(pMsgBox);          
        
        SF_LOG_I("vec Size:%zu;", m_vMsgBox.size());   
        
    } while ( false );
    
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
void SfWindowsManager::DestroyAllMsgBox()
{
    SF_LOG_I("Called; %zu;",m_vMsgBox.size()); 
    
    for (int i = (m_vMsgBox.size()-1) ; i>=0 ; i-- )
    {
        SfMessageBox *pMsgBox = ((SfMessageBox*)m_vMsgBox[i]);
        if (pMsgBox != NULL)
        {
            pMsgBox->Destroy();   
            m_vMsgBox.erase (m_vMsgBox.begin()+i);
            SF_LOG_I("DeleteAllMsgBox->erase(left:%zu)", m_vMsgBox.size()); 
        }           
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::DestroyMsgBox(SfMessageBox* pMsgBox)
{
    SF_LOG_I("Called;"); 

    for (int i = (m_vMsgBox.size()-1) ; i>=0 ; i-- )
    {
        SF_LOG_I("[%p];", pMsgBox);
        SF_LOG_I("m_vMsgBox[%d]=%p;", i, m_vMsgBox[i]);
        if ( (void*)m_vMsgBox[i] == (void*)pMsgBox )
        {
            m_vMsgBox.erase (m_vMsgBox.begin()+i);
            SF_LOG_I("Found MsgBox->erase(left:%zu);", m_vMsgBox.size()); 
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
SF_STATUS SfWindowsManager::ShowMsgBox(SfMessageBox* pMsgBox, const char* message)
{   
    SF_STATUS status = SF_STATUS_FAIL;
    if ( pMsgBox != NULL && message != NULL )
    {
        status = pMsgBox->Show(message); 
    }
    else
    {
        SF_LOG_E("Invalid messagebox parameters");    
    }    
    return status;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfWindowsManager::MsgBoxOkButtonCb(MessageBoxButtonCbParam* pData)
{
    SF_LOG_I( "Called;" );    

    if ( pData != NULL && pData->pUserParam != NULL )
    {
        SfWindowsManager* pManager = static_cast<SfWindowsManager*> (pData->pUserParam->pContext);
        if ( pManager != NULL )
        {
            SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData->pUserParam->pParam);
            pManager->DestroyMsgBox(pMsgBox);
        }
    }        
    else
    {
        SF_LOG_E("Invalid parameters was passed;");
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfWindowsManager::MsgBoxYesButtonCb(MessageBoxButtonCbParam* pData)
{
    SF_LOG_I( "Called;" );    

    if ( pData != NULL && pData->pUserParam != NULL )
    {
        SfWindowsManager* pManager = static_cast<SfWindowsManager*> (pData->pUserParam->pContext);
        if ( pManager != NULL )
        {
            SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData->pUserParam->pParam);
            pManager->DestroyMsgBox(pMsgBox);
        }
    }        
    else
    {
        SF_LOG_E("Invalid parameters was passed;");
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfWindowsManager::MsgBoxNoButtonCb(MessageBoxButtonCbParam* pData)
{
    SF_LOG_I( "Called;" );    

    if ( pData != NULL && pData->pUserParam != NULL )
    {
        SfWindowsManager* pManager = static_cast<SfWindowsManager*> (pData->pUserParam->pContext);
        if ( pManager != NULL )
        {
            SfMessageBox* pMsgBox = static_cast<SfMessageBox*> (pData->pUserParam->pParam);
            pManager->DestroyMsgBox(pMsgBox);
        }
    }        
    else
    {
        SF_LOG_E("Invalid parameters was passed;");
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::CreateBlockedListWindow(Bool isFromKernel)
{
    SF_LOG_I("Called;");
    if( m_pBlockedListWindow != NULL )
    {
        if ( SF_FAILED( m_pBlockedListWindow->Create() ) )
        {
            SF_LOG_E("Blocked list window has not been created.");
            return SF_STATUS_FAIL;
        }
        m_pBlockedListWindow->SetFromKernel(isFromKernel);
    }
    else
    {
        SF_LOG_E("Blocked list window has not been initialized.");
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::DestroyBlockedListWindow()
{
    SF_LOG_I("Called;");
    SF_STATUS status = SF_STATUS_FAIL;
    if( m_pBlockedListWindow != NULL )
    {
        status = m_pBlockedListWindow->Destroy();
    }
    
    return status;
}


/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::ShowBlockedListWindow( SF_WINDOW_TYPE Type )
{
    SF_LOG_I("Called;");
    if (m_pBlockedListWindow)
    {
        m_pBlockedListWindow->m_ListWindowType = Type;
    }
    else
    {
        SF_LOG_E("Blocked list instnace is NULL.");
        return SF_STATUS_FAIL;
    }
    return (m_pBlockedListWindow != NULL) ? m_pBlockedListWindow->Show() : SF_STATUS_FAIL;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::CreateReporterWindow()
{
    SF_LOG_I("Called;");
    if( m_pReporterWindow != NULL )
    {
        if ( SF_FAILED( m_pReporterWindow->Create() ) )
        {
            SF_LOG_E("Scan window has not been created.");
            return SF_STATUS_FAIL;
        }
    }
    else
    {
        SF_LOG_E("Scan window has not been initialized.");
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfWindowsManager::DestroyReporterWindow()
{
    SF_LOG_I("Called;");
    SF_STATUS status = SF_STATUS_FAIL;
    if( m_pReporterWindow != NULL )
    {
        status = m_pReporterWindow->Destroy();
    }

    return status;
}


