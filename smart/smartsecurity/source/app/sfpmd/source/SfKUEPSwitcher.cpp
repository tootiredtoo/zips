/**
****************************************************************************************************
* @file SfKUEPSwitcher.cpp
* @brief Security framework [SF] class interface for tasks/plugins(antimalware,devicecontrol etc.).
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jan 14, 2015
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
// local
#include "SfKUEPSwitcher.h"

// project
#include "libcore/SfMemory.h"
#include "libprimitive/SfFs.h"
#include "libprotocol/SfPacket.h"
#include "libprotocol/SfOperationsFormat.h"
#include "libsfkc/SfKernelConnection.h"

// system
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <vconf.h>
#include <dirent.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <tzplatform_config.h>

#include <sys/types.h>
#include <sys/stat.h>

SfKUEPSwitcher::SfKUEPSwitcher() : ISfThread("SfKUEPSwitcher")
{
}

SfKUEPSwitcher::~SfKUEPSwitcher()
{
    ISfThread::Stop();
    ISfThread::Join();
}

SF_STATUS SfKUEPSwitcher::Execute()
{
    SF_STATUS result;
    SF_LOG_I("Called;");
    result = ISfThread::Run();
    ISfThread::Join();
    return result;
}

void SfKUEPSwitcher::ThreadFunction()
{
    SF_LOG_I("++");
    SendDUIDToKernel();
    FindUEPDisableFile();
    SF_LOG_I("--");
}

SF_STATUS SfKUEPSwitcher::SendDUIDToKernel() const
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

static void DisableKUEP(const std::string& disablePath)
{
    if (GetUrgentEscapeScan() == TRUE) {
        SF_LOG_E("urgent escapse");
        return;
    }

    SF_LOG_I("Try to disable kUEP;");

    void *pHandle = dlopen(disablePath.c_str(), RTLD_LAZY);
    if (!pHandle) {
        SF_LOG_E( "dlopen() failed, error = [%s];", dlerror() );
        return;
    }

    SF_LOG_I("KUEP is Disabled;");
    sync();
    dlclose(pHandle);
}

static void CreateDuidToUSBStorage(const std::string& usbRootPath)
{
    if (GetUrgentEscapeScan() == TRUE) {
        SF_LOG_E("urgent escapse");
        return;
    }

    const char* const duidFileName = "VDUEPOFF.uid"; // DUID file name
    std::ofstream outFile((usbRootPath + duidFileName).c_str(), std::ofstream::trunc);
    if (!outFile.is_open()) {
        SF_LOG_E("open file failed;");
        return;
    }

    const Char sc_vconfHWDUIDKey[] = "db/comss/hwduid";
    char* duid = vconf_get_str(sc_vconfHWDUIDKey);
    if (duid == NULL) {
        SF_LOG_E("Hwduid get failed;");
        return;
    }

    outFile << std::string(duid) << std::flush;
    outFile.close();
    sf_free(duid);
    sync();
    SF_LOG_I("DUID file is created;");
}

void SfKUEPSwitcher::FindUEPDisableFile()
{
    DIR *usbRootDir;
    struct dirent *dirUSBDrive;
    SF_LOG_I("Called;");

    if (GetUrgentEscapeScan() == TRUE) {
        SF_LOG_E("urgent escapse");
        return;
    }

    std::string usbRootPath = tzplatform_mkpath(TZ_SYS_STORAGE, "");
    usbRootDir = opendir(usbRootPath.c_str());
    if (usbRootDir) {
        // Iterate through each entry in the directory
        while ((dirUSBDrive = readdir(usbRootDir)) != NULL) {
            // Skip "." and ".." entries
            if (strncmp(dirUSBDrive->d_name, ".", sizeof(".")) == 0 || strncmp(dirUSBDrive->d_name, "..", sizeof("..")) == 0) {
                continue;
            }

            // Construct the full path for USBDrive if any:
            const char* const USBType = "USBDrive";
            if (strstr(dirUSBDrive->d_name, USBType) != NULL) {
                const char* const disableCerName = "VDUEPOFF.cer";
                std::string disablePath = usbRootPath + "/" + dirUSBDrive->d_name + "/" + disableCerName;
                if (FileExists(disablePath) == true) {
                    SF_LOG_I("Found file for disable kUEP");
                    DisableKUEP(disablePath);
                    break;
                }

                const char* const duidGetName = "VDUEPOFF.get";
                std::string hwDuidPath = usbRootPath + "/" + dirUSBDrive->d_name + "/" + duidGetName;
                if (FileExists(hwDuidPath) == true) {
                    if (IsSymbolic(hwDuidPath) == false) {
                        SF_LOG_I("Found file to get DUID");
                        CreateDuidToUSBStorage(usbRootPath);
                    }
                    break;
                }
            }

        }
        closedir(usbRootDir);
    }
}
