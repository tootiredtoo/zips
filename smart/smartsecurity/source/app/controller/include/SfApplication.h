/**
****************************************************************************************************
* @file SfApplication.h
* @brief Security framework [SF] Tizen IU application main class
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created Aug 27, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_APPLICATION_H_
#define _SF_APPLICATION_H_

#include "SfCommon.h"

#include "libcore/SfCore.h"
#include "libprovider/SfSettings.h"
#include "SfWindowsManager.h"

//Migration TZTV2.4
#include <app_control.h>
#include <app_control_internal.h>
#include <vconf.h>


#define CAN_CALL_MULTIPLE

/**
****************************************************************************************************
* @brief SF UI application main context
****************************************************************************************************
*/
struct SfApplicationContext
{
    SfApplicationContext()
        : header()
        , pApplicationName( NULL )
        , pArguments( NULL )
    {}
    ~SfApplicationContext() {}

    SfContextHeader header; ///< Application context header
    Char* pApplicationName; ///< Application name
    Char* pArguments; ///< Application internal arguments (currently not used)
}; // struct SfApplicationContext

/**
****************************************************************************************************
* @brief Clear the application context. This function called in the macros of safe initialization
* @see SF_CONTEXT_SAFE_INITIALIZATION
****************************************************************************************************
*/
void SfApplicationContextUninit(SfApplicationContext* pContext);

/**
****************************************************************************************************
* @brief Security Framework UI application
****************************************************************************************************
*/
class SfApplication
{
    
public:
    /**
    ************************************************************************************************
    * @brief Default application contructor
    ************************************************************************************************
    */
    SfApplication();

    /**
    ************************************************************************************************
    * @brief Application destructor
    ************************************************************************************************
    */
    ~SfApplication();

    /**
    ************************************************************************************************
    * @brief Return application context pointer
    * @return Constant pointer to the application context
    ************************************************************************************************
    */
    const SfApplicationContext* GetContext() const;

    /**
    ************************************************************************************************
    * @brief Creates application object
    * @param [in] argc Pointer to the argc argument of the main function
    * @param [in] argv Triple pointer to the argv aprument of the main function
    * @note Triple pointer it is requirement of the EFL framework
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Create(int* argc, char*** argv);

    /**
    ************************************************************************************************
    * @brief Destroying application object
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */
    SF_STATUS Destroy();

    /**
    ************************************************************************************************
    * @brief Dispatch the event to the corresponding part of the application
    * @param window Type of the window to which event will be dispatched
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */
    SF_STATUS Dispatch(SF_WINDOW_TYPE window, char* args);

    /**
    ************************************************************************************************
    * @brief This function called when Tizen sends OnCreate signal to the application.
    * @details The callback function is called before the main loop of application starts. In this
    *   callback you can initialize application resources like window creation, data structure, etc.
    *   After this callback function returns @c true, the main loop starts up and
    *   SfServiceApplicationHandler is subsequently called. If this callback function returns @c
    *   false, the main loop doesn't start and SfTerminateApplicationHandler is subsequently called.
    * @param [in] pApplication Pointer to the application object
    * @see SfApplicationContext
    * @return TRUE on success, FALSE - otherwise
    ************************************************************************************************
    */
    static bool SfCreateApplicationHandler(void* pApplication);

    /**
    ************************************************************************************************
    * @brief This function called when Tizen sends OnService signal to the application
    * @details When the application is launched, this callback function is called after the main
    *   loop of application starts up. The passed service handle describes the launch request and
    *   contains the information about why the application is launched. If the launch request is
    *   sent to the application on running or pause state, this callback function can be called
    *   again to notify that he application is asked to be launched.
    * @param [in] service Information about requested service
    * @param [in] pApplication Pointer to the application object
    * @see SfApplicationContext
    * @return void
    ************************************************************************************************
    */
    static void SfServiceApplicationHandler(app_control_h service, void* pApplication);

    /**
    ************************************************************************************************
    * @brief This function called when Tizen sends OnPause signal to the application
    * @details The application is not terminated and still running in paused state.
    * @param [in] pApplication Pointer to the application object
    * @see SfApplicationContext
    * @return void
    ************************************************************************************************
    */
    static void SfPauseApplicationHandler(void* pApplication);

    /**
    ************************************************************************************************
    * @brief This function called when Tizen sends OnResume signal to the application
    * @details This callback function is not called when the application moved from created state to
    *   running state.
    * @param [in] pApplication Pointer to the application object
    * @see SfApplicationContext
    * @return void
    ************************************************************************************************
    */
    static void SfResumeApplicationHandler(void* pApplication);

    /**
    ************************************************************************************************
    * @brief This function called when Tizen sends OnTerminate signal to the application
    * @param [in] pApplication Pointer to the application object
    * @see SfApplicationContext
    * @return void
    ************************************************************************************************
    */
    static void SfTerminateApplicationHandler(void* pApplication);

private:
    /**
    ************************************************************************************************
    * @brief Copy contructor of the class
    * @note It's declared but not implemented, since currently this class, doesn't support copying.
    ************************************************************************************************
    */
    SfApplication(const SfApplication& application); // blocked

    /**
    ************************************************************************************************
    * @brief Assignment operator of the SfApplication class
    * @note It's declared but not implemented, since  currently this class doesn't support
    *   assignment
    ************************************************************************************************
    */
    const SfApplication& operator = ( const SfApplication& mutex ); // blocked
    
    /**
    ************************************************************************************************
    * @brief Create and show BlockedListWindow;
    * @return SF_STATUS_OK on success, SF_STATUS_FAIL - otherwise
    ************************************************************************************************
    */
    SF_STATUS ShowBlockedListWindow();
    /**
    ****************************************************************************************************
    * @brief Perform checking of the context by validating structure size and pointer state. In case if 
    *        structure was not initialized yet, it will be filled by valid data. If context structure
    *        contains valid data, context will be closed and objectErrHandler will be called.
    * @param [in,out] SfApplicationContext Pointer to the object that contains context header structure
    * @param [in] Version Version of the context object
    ****************************************************************************************************
    */
    SF_STATUS SfContextSafeInitialization(SfApplicationContext* pContext, const Uint32 version );

private:
    /**
    ************************************************************************************************
    * @brief Pointer to the application context
    * @note The main idea of creation pointer instead of real member, is possibility to create an
    *   worker object on it's necessity and by passing previously save application context
    *   continue it's work.
    ************************************************************************************************
    */
    SfApplicationContext*   m_pContext; ///< Pointer to application context

    SfWindowsManager*       m_pSfWindowsManager; ///< Pointer to window manager instance
};

#endif /* _SF_APPLICATION_H_ */