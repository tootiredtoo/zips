/**
****************************************************************************************************
* @file main.cpp
* @brief Security framework [SF]
* @author Anton Skakun (a.skakun@samsung.com)
* @author Oleksandr Biriukov (o.biryukov@samsung.com)
* @date Created Mar 22, 2014 11:40.
* @date Modified 06 Dec, 2018
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
// local
#include "SfTaskMessageReceiver.h"
#ifdef USE_PLUGIN
#include "SfKUEPSwitcher.h"
#endif 
#include "SfRecorder.h"

// project
#include "common/SfJSONTags.h"
#include "libprimitive/SfSignalHandler.h"
#include "libprimitive/SfFs.h"
#include "libcore/SfDebug.h"
#include "libprimitive/SfStringUtils.h"

// system
#include <dd-power.h>
#include <vconf.h>
#include <fstream>
#include <unistd.h>
#include <usb-device.h>
#ifdef SAMSUNG_PRODUCT
#include <smart-deadlock.h>
#endif
#include <glib.h>
#include <glib-unix.h>
#include <string.h>
#include <fcntl.h>
#include <sstream>

#define SF_USE_PTHREAD_AFTER_INSTANT_ON
#define SF_SFPMD_ELF_PATH "/usr/bin/sfpmd"

/*
****************************************************************************************************
* @brief If when usb device is off, processing file will be stopped.
****************************************************************************************************
*/
extern Bool gsf_usb_device_off;
extern Bool gsf_power_off;

static volatile int sf_term_received = 0;

void sf_force_close_USBDrive(void)
{
        char buf[PATH_MAX];
        char buf2[PATH_MAX];
        int fd, ret;
        const int max_fd = sysconf(_SC_OPEN_MAX); // Get the maximum number of open file descriptors

        for (fd = 0; fd < max_fd; fd++) {
                if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
			//                        SF_LOG_I("File descriptor %d is open", fd);
                        snprintf(buf, PATH_MAX, "/proc/self/fd/%d", fd);

                        if ((ret = readlink(buf, buf2, PATH_MAX)) < 0)
                                continue;

                        buf2[ret == PATH_MAX ? PATH_MAX - 1 : ret] = '\0';
			if (strstr(buf2, "USBDrive") != NULL) {
				SF_LOG_E("Closing fd %d at: %s", fd, buf2);
				ret = close(fd);
				if (ret == -1) {
					SF_LOG_E("Close error: %d", errno);
				}
			}

                }
        }
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
static void sf_usb_mount(void)
{
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
static void sf_usb_umount(void)
{
    // Close opened descriptors if any to unblock suspend
    sf_force_close_USBDrive();
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static int sf_power_wake_callback(int reason, void* pData)
{
    SF_LOG_I("[reason:%d];", reason);

    gsf_usb_device_off = FALSE;
    gsf_power_off = FALSE;
    SetUrgentEscapeScan(FALSE);
    return 0;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static int sf_power_off_callback(int reason, void *pData)
{
    SF_LOG_I("[reason:%d];", reason);

    gsf_power_off = TRUE;
    SetUrgentEscapeScan(TRUE);
    return 0;
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
static void sf_usb_device_connected_callback(usb_device_h usb_device, char *action, void *user_data)
{
    int type;
  
    if (!usb_device)
        return;
  
    type = usb_device_get_class(usb_device);
    if (type != USB_MASS_STORAGE) {
        free_usb_device_h(usb_device);
	return;
    }

    if (!strncmp(action, "mounted", sizeof("mounted"))) {
        /* USB device is mounted and mount will accessible after this event */
	SF_LOG_I("USB Device is mounted");	
        sf_usb_mount();
    }
	  
    if (!strncmp(action, "blocked", sizeof("blocked"))) {
        /* USB device will be unmounted soon. Do not use the mount path as after 500 ms unmounting will start & process access the mount the will be terminated for debug/perf image */
	SF_LOG_I("USB Device going to umount");	
        sf_usb_umount();
    }
  
    free_usb_device_h(usb_device);
}


/**
****************************************************************************************************
*
****************************************************************************************************
*/
static void sf_exit( SF_STATUS status, const Char* message )
{
	if ( SF_FAILED( status ) ) {
		SF_LOG_E( "%s", message );
	} else {
		SF_LOG_I( "%s", message );
	}
    //power_unsubscribe_poweroff( PowerOffCallback );
	exit( status );
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void sf_show_warning_notification( SfSignalHandler& sigHandler )
{
    try {
#ifdef SHOW_SMARTSECURITY_POPUP
        SfPushNotification notif( "sfpmd", "plugin manager daemon" );
        notif.ShowNotification( "Someone try to kill sfpmd!" );
#endif
        SF_LOG_E( "Someone send signal to sfpmd!" );
        SelfReport selfReport;
        selfReport.reportData["caller"] = CALLER_FIELD;
        std::ostringstream reportStream;
        reportStream << "message: Signal has been received by sfpmd, " << "process: " << sigHandler.GetSenderProcessName() << ", signal: " << std::to_string(sigHandler.GetSignal());
        SfRecorder reportHandler;
        selfReport.description = reportStream.str();
        SF_STATUS ret = reportHandler.SendLogToSCS(&selfReport);
        SF_LOG_I("sendReport done[%d]", ret);
        sigHandler.ResetReceivedSignal();
    }
    catch(const std::exception& e) {
        SF_LOG_E("[Exception Error : %s]", e.what());
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static void sf_wait_before_starting(Int32 seconds)
{
    try {
        SF_LOG_I("%d secs;", seconds);

        SfSignalHandler& sigHandler = SfSignalHandler::GetInstance();
        if (/*SF_FAILED(sigHandler.CatchSignal(SIGTERM)) ||*/
            SF_FAILED(sigHandler.CatchSignal(SIGHUP)) ||
            SF_FAILED(sigHandler.CatchSignal(SIGINT)) ||
            SF_FAILED(sigHandler.CatchSignal(SIGABRT)) ||
            SF_FAILED(sigHandler.CatchSignal(SIGQUIT)) ||
            SF_FAILED(sigHandler.CatchSignal(SIGTSTP)) ||
            SF_FAILED(sigHandler.CatchSignal(SIGUSR1)) ||
            SF_FAILED(sigHandler.CatchSignal(SIGUSR2)) ||
            SF_FAILED(sigHandler.CatchSignal(SIGPIPE))) {
            sf_exit(SF_STATUS_FAIL, "Init signal handle failed;");
        }

        while (seconds-- > 0) {
            if (sigHandler.IsSignalReceived()) {
                sigHandler.PrintReceivedSignal();
                if (sigHandler.IsSignalReceived(SIGTERM)) {
                    sf_exit(SF_STATUS_OK, "term signal arrived;");
                }
                sf_show_warning_notification(sigHandler);
            }
            SfSleepMs(c_second);
        }
    }
    catch (std::exception &e) {
        SF_LOG_E("Exception: %s;", e.what());
    }
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
gboolean sf_notify_callback(gpointer data)
{
#ifdef SAMSUNG_PRODUCT
    smart_deadlock_watchdog_notify();
#endif
    // SF_LOG_I( "%s(): smart_deadlock_watchdog_notify;", __func__ );
    return TRUE;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
static SecurityReport::ReportTaskWorker dataSizeChecker;
static SecurityReport::ReportTaskWorker cclogSizeChecker;

gboolean sf_check_rw_usage(gpointer data)
{
    dataSizeChecker.Execute(SecurityReport::GET_RW_SIZE);
    cclogSizeChecker.Execute(SecurityReport::GET_CC_SIZE);
    return TRUE;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
gboolean sf_signal_term_catch(gpointer user_data)
{
    if (user_data == NULL)
    {
        return G_SOURCE_REMOVE;
    }
    GMainLoop *main_loop = (GMainLoop *)user_data;
    g_main_loop_quit(main_loop);

    return G_SOURCE_REMOVE;
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void* sf_signal_catch(void* pData)
{
    if (pData == NULL) {
        return NULL;
    }

    char *threadName = "sf_signal_catch";
    pthread_setname_np(pthread_self(), threadName);

    SfSignalHandler &sigHandler = SfSignalHandler::GetInstance();
    while (!sf_term_received) {
        if (sigHandler.IsSignalReceived()) {
            sigHandler.PrintReceivedSignal();
            if (sigHandler.IsSignalReceived(SIGTERM) || sigHandler.IsSignalReceived(SIGHUP)) {
                break;
            }

            if (sigHandler.IsSignalReceived(SIGPIPE) || sigHandler.IsSignalReceived(SIGUSR1) || sigHandler.IsSignalReceived(SIGUSR2)) {
                sigHandler.ResetReceivedSignal();
                continue;
            }
            sf_show_warning_notification(sigHandler);
        }
        SfSleepMs(c_second);
    } // end while
    sf_term_received = 0;
    return NULL;
}

#ifdef USE_PLUGIN

#define EXPORT __attribute__((visibility("default")))

extern "C" {
	EXPORT int run(void);
	EXPORT int stop(void);


	static GMainLoop *main_loop = NULL;


static SF_STATUS SendDUIDToKernel() 
{
    SF_LOG_I("Called;");

    SfKernelConnection kConnection;
    if (SF_FAILED(kConnection.Connect())) {
        SF_LOG_E( "Connect() failed;" );
        return SF_STATUS_FAIL;
    }

    const Char sc_vconfHWDUIDKey[] = "db/comss/hwduid";
    char *duid = vconf_get_str(sc_vconfHWDUIDKey);
    if (duid == NULL) {
        SF_LOG_E("Hwduid get failed;");
        return SF_STATUS_FAIL;
    }

    const size_t c_operationSize = sizeof(SfOperationSetupDUID);
    const size_t c_duidLength = strlen(duid) + 1;
    SfOperationSetupDUID* pOperationDUID = (SfOperationSetupDUID*)malloc(c_operationSize);
    pOperationDUID->header.size = (size_t)c_operationSize;
    pOperationDUID->header.type = SF_OPERATION_TYPE_SETUP_DUID;
    pOperationDUID->pDUID = (Char*)malloc(c_duidLength);
    strncpy(pOperationDUID->pDUID, duid, c_duidLength);

    SfPacket packet;
    packet.header.size = sizeof(SfPacket);
    packet.header.type = SF_PACKET_TYPE_OPERATION;
    packet.env = NULL;
    packet.op = (SfProtocolHeader*)pOperationDUID;

    int ret = kConnection.Send(&packet);
    if (SF_FAILED(ret)) {
	    SF_LOG_E("Send() failed;");
    } else {
	    SF_LOG_I("Send(DUID) success;");
    }
    SfDestroyOperation((SfProtocolHeader*)pOperationDUID);
    sf_free(duid);
    return SF_STATUS_OK;
}


EXPORT int run()
{
	GMainContext *ps_context;

	SF_LOG_I( "started;" );

	// Create console log if needed
	create_console_log_event_loop();

	ps_context = g_main_context_new();
	g_main_context_push_thread_default(ps_context);

	// register usb device event callback
	usb_set_connected_cb(sf_usb_device_connected_callback, NULL);

	if (device_power_subscribe_poweroff(sf_power_off_callback, NULL) != 0) {
		SF_LOG_E( "poweroff subcribe failed;" );
	}

	if (device_power_subscribe_wakeup(sf_power_wake_callback, NULL) != POWER_ERROR_NONE) {
		SF_LOG_E( "wakeup subscribe failed;" );
	}

	sf_wait_before_starting(0);

	//	SfKUEPSwitcher kuepSwitcher;
	//	kuepSwitcher.Execute();
	SF_STATUS status;
	if ((status = SendDUIDToKernel()) != SF_STATUS_OK) {
		SF_LOG_E( "SendDUIDToKernel failed: %d;", status);
	}

	SfTaskMessageReceiver::GetInstance();

	SecurityReport::ReportTaskWorker reportCleanWorker;
	reportCleanWorker.Execute(SecurityReport::CLEAR);

	SecurityReport::ReportTaskWorker sharedCleanWorker;
	sharedCleanWorker.Execute(SecurityReport::SHARED_CLEAR);

	SecurityReport::ReportTaskWorker cclogCleanWorker;
	cclogCleanWorker.Execute(SecurityReport::CCLOG_CLEAR);

	guint rw_usage_id = 0;
	guint sighup_id = 0;

	pthread_t th_id = 0;
	Int32 err = -1;

	try {
		main_loop = g_main_loop_new(ps_context, FALSE);

		sf_term_received = 0;
		err = pthread_create(&th_id, NULL, sf_signal_catch, (void*)main_loop);
		if (0 != err) {
			SF_LOG_E("[create error%d];", err);
		}

		const int rw_check_cycle = 1000 * 60 * 60; // 1 hour
		rw_usage_id = g_timeout_add(rw_check_cycle, sf_check_rw_usage, main_loop);

		sighup_id = g_unix_signal_add(SIGHUP, sf_signal_term_catch, main_loop);

		g_main_loop_run(main_loop);
	}
	catch (std::exception &x) {
		g_error("Exception : %s", x.what());
	}

	SF_LOG_I( "g_main_loop exited" );

	if (rw_usage_id) g_source_remove(rw_usage_id);
	if (sighup_id) g_source_remove(sighup_id);
	if (main_loop) g_main_loop_unref(main_loop);
	if (ps_context) {
		g_main_context_pop_thread_default(ps_context);
		g_main_context_unref(ps_context);
	}

	if (th_id) {
		sf_term_received = 1;
		err = pthread_join(th_id, NULL);
		if (0 != err) {
			SF_LOG_E("join error:%d;", err);
		}
		th_id = 0;
	}

	SfTaskMessageReceiver::ReleaseInstance();

	device_power_unsubscribe_wakeup(sf_power_wake_callback);
	device_power_unsubscribe_poweroff(sf_power_off_callback);

	usb_unset_connected_cb();
	destroy_console_log_event_loop();
	SF_LOG_I( "finished;" );
	return 0;
}

EXPORT int stop()
{
	SF_LOG_I( "started;" );
	if (!main_loop) {
		SF_LOG_E("[No plugin started yet!]");
		return -1;
	}

	g_main_loop_quit(main_loop);

	SF_LOG_I( "finished;" );
	return 0;
}

}



#else
/**
****************************************************************************************************
*
****************************************************************************************************
*/
Int main()
{
    SF_LOG_I( "started;" );
    // Create console log if needed
    create_console_log_event_loop();

    // register usb device event callback
    usb_set_connected_cb(sf_usb_device_connected_callback, NULL);

    if (device_power_subscribe_poweroff(sf_power_off_callback, NULL) != 0) {
        SF_LOG_E( "poweroff subcribe failed;" );
    }

    if (device_power_subscribe_wakeup(sf_power_wake_callback, NULL) != POWER_ERROR_NONE) {
        SF_LOG_E( "wakeup subscribe failed;" );
    }

    sf_wait_before_starting(0);

    SfKUEPSwitcher kuepSwitcher;
    kuepSwitcher.Execute();

    SfTaskMessageReceiver::GetInstance();

    SecurityReport::ReportTaskWorker reportCleanWorker;
    reportCleanWorker.Execute(SecurityReport::CLEAR);

    SecurityReport::ReportTaskWorker sharedCleanWorker;
    sharedCleanWorker.Execute(SecurityReport::SHARED_CLEAR);

    SecurityReport::ReportTaskWorker cclogCleanWorker;
    cclogCleanWorker.Execute(SecurityReport::CCLOG_CLEAR);

    guint timeout_id = 0;
    guint rw_usage_id = 0;
    guint sigterm_id = 0;
    guint sighup_id = 0;
    GMainLoop *main_loop = NULL;

    pthread_t th_id = 0;
    Int32 err = -1;

    try {
        main_loop = g_main_loop_new(NULL, FALSE);

#ifdef SAMSUNG_PRODUCT
        const int watchdog_timeout = 120;
        int nRetWatchdog = smart_deadlock_register_watchdog_service(watchdog_timeout);
        SF_LOG_I("[set SDL:%d];", nRetWatchdog);
#endif

        sf_term_received = 0;
        err = pthread_create(&th_id, NULL, sf_signal_catch, (void*)main_loop);
        if (0 != err) {
            SF_LOG_E("[create error%d];", err);
        }

        const int smdl_notify_cycle = 10000;
        timeout_id = g_timeout_add(smdl_notify_cycle, sf_notify_callback, main_loop);

        const int rw_check_cycle = 1000 * 60 * 60; // 1 hour
        rw_usage_id = g_timeout_add(rw_check_cycle, sf_check_rw_usage, main_loop);

        sigterm_id = g_unix_signal_add(SIGTERM, sf_signal_term_catch, main_loop);

        sighup_id = g_unix_signal_add(SIGHUP, sf_signal_term_catch, main_loop);

        g_main_loop_run(main_loop);
    }
    catch (std::exception &x) {
        g_error("Exception : %s", x.what());
    }

    if (timeout_id) g_source_remove(timeout_id);
    if (rw_usage_id) g_source_remove(rw_usage_id);
    if (sigterm_id) g_source_remove(sigterm_id);
    if (sighup_id) g_source_remove(sighup_id);
    if (main_loop) g_main_loop_unref(main_loop);

    if (th_id) {
        sf_term_received = 1;
        err = pthread_join(th_id, NULL);
        if (0 != err) {
            SF_LOG_E("join error:%d;", err);
        }
        th_id = 0;
    }

    SfTaskMessageReceiver::ReleaseInstance();

    device_power_unsubscribe_wakeup(sf_power_wake_callback);
    device_power_unsubscribe_poweroff(sf_power_off_callback);
 
    usb_unset_connected_cb();
    destroy_console_log_event_loop();

    SF_LOG_I( "exit;" );
    return SF_STATUS_OK;
}
#endif // USE_PLUGIN
