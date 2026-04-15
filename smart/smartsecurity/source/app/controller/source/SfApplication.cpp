// local
#include "SfApplication.h"
#include "libcore/SfDebug.h"

// project
#include "libprimitive/UnixSocket.h"
#include "libprimitive/SfSharedFile.h"
#include "libcore/SfCore.h"
#include "common/SfTasksTags.h"
#include "common/SfJSONTags.h"
#include "common/SfPushNotification.h"
#include "libprovider/SfSettings.h"


// system
#include <app.h>
#include <jsoncpp/json/json.h>
#include <unistd.h>
#include <uifw_misc.h>
#include <efl_assist.h>

#if NO_AUDIO
#include <voice_control_elm.h>
#include <voice_control_elm_private.h>
#endif

/**
****************************************************************************************************
* @brief Static application callback structure that defines basic handlers for EFL application
* @see app_event_callback_s
****************************************************************************************************
*/
static ui_app_lifecycle_callback_s s_applicationEventHandlers =
{
    .create = SfApplication::SfCreateApplicationHandler, ///< OnCreate event
    .terminate = SfApplication::SfTerminateApplicationHandler, ///< OnTerminate event
    .pause = SfApplication::SfPauseApplicationHandler, ///< OnPause event
    .resume = SfApplication::SfResumeApplicationHandler, ///< OnResume event
    .app_control = SfApplication::SfServiceApplicationHandler, ///< OnService event
};

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfIsFit( void* pData )
{
    if ( NULL == pData )
    {
        SF_LOG_E("pData is NULL;" );
        return SF_STATUS_FAIL;
    }

    SfApplication* pApplication = static_cast<SfApplication*>(pData);
    if (pApplication == NULL ||
        pApplication->GetContext()->header.size != sizeof(SfApplicationContext) ||
        pApplication->GetContext()->header.state != SF_CONTEXT_STATE_INITIALIZED)
    {
        SF_LOG_E("context is not fit [size %d | %zu ; state %d | %d];",
                 pApplication->GetContext()->header.size, sizeof(SfApplicationContext),
                 pApplication->GetContext()->header.state, SF_CONTEXT_STATE_INITIALIZED);
        return SF_STATUS_FAIL;
    }

    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfApplication::SfApplication()
    : m_pContext( NULL )
    , m_pSfWindowsManager ( NULL )
{
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SfApplication::~SfApplication()
{
}
/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfApplication::SfContextSafeInitialization(SfApplicationContext* pContext, const Uint32 version )
{
    SF_STATUS contextinitResult = SF_STATUS_FAIL;
    if(!SfIsContextInitialized(&pContext->header, sizeof(SfApplicationContext))){
        pContext->header.size    = sizeof(SfApplicationContext);
        pContext->header.version = version;
        contextinitResult        = SF_STATUS_OK;
    }
    else{
        SF_LOG_E("The #objectName was requested to be initailized twice or it has invalid structure");
    }
    return contextinitResult;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfApplication::Create(int* pArgc, char*** pArgv)
{
#ifdef CAN_CALL_MULTIPLE
    SF_LOG_I("Create[%p]", this);
    if (m_pContext)
    {
        SF_LOG_I("[already started.]");
        return SF_STATUS_OK;
    }
#endif /* CAN_CALL_MULTIPLE */ 
    m_pContext = (SfApplicationContext*) malloc(sizeof(SfApplicationContext));
    if ( NULL == m_pContext )
    {
        SF_LOG_E("m_pContext is NULL;");
        return SF_STATUS_FAIL;
    }

    if( SF_FAILED(SfContextSafeInitialization(m_pContext, 0xbedabeda)))
    {
        SF_LOG_E("Init context failed;");
        return SF_STATUS_FAIL;
    }
    
    if ( m_pSfWindowsManager == NULL )
    {
        m_pSfWindowsManager = new SfWindowsManager();
        m_pSfWindowsManager->Create( );
        //SF_LOG_I("Create SfWindowManager");
    }
    
    m_pContext->header.state = SF_CONTEXT_STATE_INITIALIZED;
    if ( 0 != ui_app_main(*pArgc, *pArgv, &s_applicationEventHandlers, (void*)this) )
    {
        SF_LOG_E("starting app failed;");
        return SF_STATUS_FAIL;
    }
    
    SF_LOG_I("App context state:%d", m_pContext->header.state);
    return SF_STATUS_OK;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS SfApplication::Destroy()
{
    SF_LOG_I("Called");
    
    if ( m_pSfWindowsManager != NULL )
    {
        m_pSfWindowsManager->Destroy();
        delete m_pSfWindowsManager;
        m_pSfWindowsManager = NULL;
        SF_LOG_W("window manager was destroied;");
    }
        
    if (NULL != m_pContext && m_pContext->header.state == SF_CONTEXT_STATE_INITIALIZED)
    {
        ui_app_exit();
        sf_free(m_pContext);
        m_pContext = NULL;
    }

    return SF_STATUS_OK;
}


SF_STATUS SfApplication::Dispatch(SF_WINDOW_TYPE window, char* args)
{
    //SF_LOG_I("Called; SfApplication::Dispatch;");
    
    SF_STATUS result = SF_STATUS_FAIL;

    if ( m_pSfWindowsManager != NULL )
    {
        result = m_pSfWindowsManager->Dispatch(window, args);
    }
    else
    {
        SF_LOG_E("Invalid Window Manager handle");
    }

    return result;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
const SfApplicationContext* SfApplication::GetContext() const
{
    return m_pContext;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfApplicationContextUninit(SfApplicationContext* pContext)
{
    SF_LOG_I("Uninit context cb" );
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
bool SfApplication::SfCreateApplicationHandler(void* pData)
{
    if ( NULL == pData )
    {
        SF_LOG_E("pData is NULL;");
        return false;
    }

    //SF_LOG_I("SfCreateApplicationHandler");

    elm_app_base_scale_set(2.0); // This value is 1920*1280 device

    ea_init(0, NULL);

    char *lang_set = vconf_get_str(VCONFKEY_LANGSET);
    if( lang_set && lang_set[0])
        SF_LOG_I("Lang:%s;", lang_set);
    else
        SF_LOG_E("Langauge set failed: %s;", lang_set);

    SF_LOG_I("locale:%s;",setlocale(LC_ALL,lang_set) );
    sf_free(lang_set);

    SF_LOG_I("%s,%s;"
        ,bindtextdomain(SF_CONTROLLER_PACKAGE,SF_SMARTSECURITY_PACKAGE_LOCALE)
        ,textdomain(SF_CONTROLLER_PACKAGE) );

    //SF_LOG_I("Create handler result = true;");
    return true;
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfApplication::SfServiceApplicationHandler(app_control_h service, void* pData)
{
    char *pWindowId = NULL;
    char *pExtraData = NULL;

    try
    {
        if (SF_FAILED(SfIsFit(pData)) || service == NULL)
        {
            char buffer[128];
            snprintf(buffer, sizeof(buffer), "Bad arguments: service = %p, pData = %p;", service, pData);
            throw std::runtime_error(std::string(buffer));
        }

#if NO_AUDIO
        vc_elm_initialize();
        vc_elm_set_auto_register_mode(1, 1);
#endif

        Ua_Orientation_Mode oMode = ua_UI_orientation_get();
        if (oMode == UA_LTR_UI_ORIENTATION)
        {
            elm_config_mirrored_set(EINA_FALSE);
        }
        else
        {
            elm_config_mirrored_set(EINA_TRUE);
        }

        int idRet = app_control_get_extra_data(service, SF_CONTROLLER_WINDOW_ID_PARAMETER, &pWindowId);
        if (idRet != APP_CONTROL_ERROR_NONE)
        {
            throw std::runtime_error("Failed to get SF_CONTROLLER_WINDOW_ID_PARAMETER");
        }

        int windowId = atoi(pWindowId);
        if (windowId < 0 || windowId >= SF_WINDOW_TYPE_MAX)
        {
            char buffer[128];
            snprintf(buffer, sizeof(buffer), "It is invalid WINDOW_TYPE: %d;", windowId);
            throw std::runtime_error(std::string(buffer));
        }
        SF_LOG_I("win Type = %s", BundleWin[(SF_WINDOW_TYPE)windowId].Type);

        if ((SF_WINDOW_TYPE)windowId == SF_WINDOW_TYPE_MSGBOX || (SF_WINDOW_TYPE)windowId == SF_WINDOW_TYPE_REPORT_NOTI)
        {
            int valRet = app_control_get_extra_data(service, SF_CONTROLLER_WINDOW_VALUE_PARAMETER, &pExtraData);
            if (valRet != APP_CONTROL_ERROR_NONE)
            {
                throw std::runtime_error("Failed to get SF_CONTROLLER_WINDOW_VALUE_PARAMETER");
            }
        }

        static_cast<SfApplication*>(pData)->Dispatch((SF_WINDOW_TYPE)windowId, pExtraData);
    }
    catch (std::exception& e)
    {
        SF_LOG_E("%s", e.what());
    }

    if (pWindowId != NULL)
    {
        sf_free(pWindowId);
        pWindowId = NULL;
    }

    if (pExtraData != NULL)
    {
        sf_free(pExtraData);
        pExtraData = NULL;
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfApplication::SfPauseApplicationHandler(void* pData)
{
    SF_LOG_I( "Called;" );
    if ( SF_SUCCESS( SfIsFit( pData ) ) )
    {
        SfApplication*      pApp = static_cast<SfApplication*>(pData);
        SfWindowsManager*   pWin = pApp->m_pSfWindowsManager;
        
        if( pWin->m_doDestroy == TRUE )
        {
            SF_LOG_I( "DESTROY;" );
#if NO_AUDIO
            vc_elm_deinitialize();
#endif
            ea_shutdown();
            pApp->Destroy();
            SF_LOG_I("Shutdown;");
            exit(0);
        }
        else
        {
            SF_LOG_I( "DON'T DESTROY;" );
            pWin->m_doDestroy = TRUE;
        }
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfApplication::SfResumeApplicationHandler(void* pData)
{
    SF_LOG_I( "Called;" );
    if ( SF_SUCCESS( SfIsFit( pData ) ) )
    {
        SF_LOG_I("Resumed;");
    }
}

/*
****************************************************************************************************
*
****************************************************************************************************
*/
void SfApplication::SfTerminateApplicationHandler(void* pData)
{
    SF_LOG_I( "Called;" );
    if ( SF_SUCCESS( SfIsFit( pData ) ) )
    {
#if NO_AUDIO
        vc_elm_deinitialize();
#endif
        ea_shutdown();
        static_cast<SfApplication*>(pData)->Destroy();
        SF_LOG_I("Shutdown;");
        exit(0);
    }
}
