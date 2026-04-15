/**
****************************************************************************************************
* @file main.cpp
* @brief Security framework [SF] main
* @author Sergey Leonov (se.leonov@samsung.com)
* @date Created Jul 30, 2014 12:46
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include "SfcAccess.h"

/**
***************************************************************************************************
*
***************************************************************************************************
*/
int main( int argc, char** argv )
{
    argc = argc;
    argv = argv;

    SF_STATUS result = SF_STATUS_FAIL;

    SfController sfc;

    result = sfc.initialize();
    if ( SF_SUCCESS(result) )
    {

        /**
        * Components
        */

        // Init SF plugin structure component
        SfComponent applicationFirewall =
        {
            .type = SF_COMPONENT_TYPE_APPLICATION,
            .componentPath = (Char*) "/mtd_rwarea/antimalware",
            .componentEnvironment = (Char*) "$PATH"
        };

        SfComponent autoScan =
        {
            .type = SF_COMPONENT_TYPE_APPLICATION,
            .componentPath = (Char*) "/mtd_rwarea/autoscan",
            .componentEnvironment = (Char*) "$PATH"
        };

        SfComponent antivirus =
        {
            .type = SF_COMPONENT_TYPE_APPLICATION,
            .componentPath = (Char*) "/mtd_rwarea/antivirus",
            .componentEnvironment = (Char*) "$PATH"
        };

        /**
        * Resources
        */
        SfResource rc1 =
        {
            .resourceType = 1,
            .resourceName = (Char*) "rc1"
        };

        SfResource rc2 =
        {
            .resourceType = 2,
            .resourceName = (Char*) "rc2"
        };

        SfResource rc3 =
        {
            .resourceType = 3,
            .resourceName = (Char*) "rc3"
        };

        /**
        * Register the components
        */
        std::cout<< std::endl << "REGISTER THE COMPONENTS: " << std::endl << std::endl;

        std::cout<< "OPERATION: SfRegisterComponent(pSfControllerContext, &applicationFirewall); RESULT: "
            << sfc.sfRegisterComponent(&applicationFirewall) << std::endl << std::endl;
        std::cout<< "OPERATION: SfRegisterComponent(pSfControllerContext, &autoScan); RESULT: "
            << sfc.sfRegisterComponent(&autoScan) << std::endl << std::endl;
        std::cout<< "OPERATION: SfRegisterComponent(pSfControllerContext, &antivirus); RESULT: "
            << sfc.sfRegisterComponent(&antivirus) << std::endl << std::endl;

        std::cout<< "LIST OF REGISTERED COMPONENTS:" << std::endl << std::endl;
        sfc.showComponentList();

        /**
        * Set component state
        */
        std::cout<< "SET COMPONENT STATE: " << std::endl << std::endl;

        std::cout<< "OPERATION: SfSetComponentState(pSfControllerContext, &applicationFirewall, SF_COMPONENT_STATE_ENABLED); RESULT: "
            << sfc.sfSetComponentState(&applicationFirewall, SF_COMPONENT_STATE_ENABLED) << std::endl << std::endl;
        std::cout<< "OPERATION: SfSetComponentState(pSfControllerContext, &autoScan, SF_COMPONENT_STATE_ENABLED); RESULT: "
            << sfc.sfSetComponentState(&autoScan, SF_COMPONENT_STATE_ENABLED) << std::endl << std::endl;
        std::cout<< "OPERATION: SfSetComponentState(pSfControllerContext, &antivirus, SF_COMPONENT_STATE_ENABLED); RESULT: "
            << sfc.sfSetComponentState(&antivirus, SF_COMPONENT_STATE_ENABLED) << std::endl << std::endl;

        std::cout<< "OPERATION: SfSetComponentState(pSfControllerContext, &applicationFirewall, SF_COMPONENT_STATE_DISABLED); RESULT: "
            << sfc.sfSetComponentState(&applicationFirewall, SF_COMPONENT_STATE_DISABLED) << std::endl << std::endl;
        std::cout<< "OPERATION: SfSetComponentState(pSfControllerContext, &autoScan, SF_COMPONENT_STATE_DISABLED); RESULT: "
            << sfc.sfSetComponentState(&autoScan, SF_COMPONENT_STATE_DISABLED) << std::endl << std::endl;
        std::cout<< "OPERATION: SfSetComponentState(pSfControllerContext, &antivirus, SF_COMPONENT_STATE_DISABLED); RESULT: "
            << sfc.sfSetComponentState(&antivirus, SF_COMPONENT_STATE_DISABLED) << std::endl << std::endl;

        /**
        * Get component state
        */
        SF_COMPONENT_STATE sfComponentState;

        std::cout<< "GET COMPONENT STATE: " << std::endl << std::endl;

        std::cout<< "OPERATION: SfGetComponentState(pSfControllerContext, &applicationFirewall, &sfComponentState); RESULT: "
            << sfc.sfGetComponentState(&applicationFirewall, &sfComponentState)
            <<", Component State: " << &sfComponentState << std::endl << std::endl;
        std::cout<< "OPERATION: SfGetComponentState(pSfControllerContext, &autoScan, &sfComponentState); RESULT: "
            << sfc.sfGetComponentState(&autoScan, &sfComponentState)
            <<", Component State: " << &sfComponentState << std::endl << std::endl;
        std::cout<< "OPERATION: SfGetComponentState(pSfControllerContext, &antivirus, &sfComponentState); RESULT: "
            << sfc.sfGetComponentState(&antivirus, &sfComponentState)
            <<", Component State: " << &sfComponentState << std::endl << std::endl;

        /**
        * Unegister the components
        */
        std::cout<< "UNREGISTER THE COMPONENTS: " << std::endl << std::endl;

        std::cout<< "OPERATION: SfUnregisterComponent(pSfControllerContext, &autoScan); RESULT: "
            << sfc.sfUnregisterComponent(&autoScan) << std::endl << std::endl;
        std::cout<< "OPERATION: SfUnregisterComponent(pSfControllerContext, &antivirus); RESULT: "
            << sfc.sfUnregisterComponent(&antivirus) << std::endl << std::endl;

        std::cout<< "LIST OF REGISTERED COMPONENTS:" << std::endl << std::endl;
        sfc.showComponentList();

        /**
        * Adding resource elements to isolated list
        */
        std::cout<< "ADD RESOURCE ELEMENTS TO ISOLATED LIST: " << std::endl << std::endl;

        std::cout<< "OPERATION: SfAddElementToList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_ISOLATED, &rc2); RESULT: "
            << sfc.sfAddElementToList(SF_RESOURCE_LIST_TYPE_ISOLATED, &rc1) << std::endl << std::endl;
        std::cout<< "OPERATION: SfAddElementToList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_ISOLATED, &rc2); RESULT: "
            << sfc.sfAddElementToList(SF_RESOURCE_LIST_TYPE_ISOLATED, &rc2) << std::endl << std::endl;

        /**
        * Adding resource elements to blocked list
        */
        std::cout<< "ADD RESOURCE ELEMENTS TO BLOCKED LIST: " << std::endl << std::endl;

        std::cout<< "OPERATION: SfAddElementToList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_BLOCKED, &rc2); RESULT: "
            << sfc.sfAddElementToList(SF_RESOURCE_LIST_TYPE_BLOCKED, &rc3) << std::endl << std::endl;

        /**
        * Get resource list
        */
        std::cout<< "GET RESOURCE LIST: " << std::endl << std::endl;

        SfResourceList sfResourceList;

        std::cout<< "OPERATION: sfGetResourceList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_ISOLATED, &sfResourceList); RESULT: "
            << sfc.sfGetResourceList(SF_RESOURCE_LIST_TYPE_ISOLATED, &sfResourceList) << std::endl << std::endl;
        std::cout<< "OPERATION: sfGetResourceList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_ISOLATED, &sfResourceList); RESULT: "
            << sfc.sfGetResourceList(SF_RESOURCE_LIST_TYPE_BLOCKED, &sfResourceList) << std::endl << std::endl;

        /**
        * Remove resource elements from isolated list
        */
        std::cout<< "OPERATION: SfRemoveElementFromList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_ISOLATED, &rc2); RESULT: "
            << sfc.sfRemoveElementFromList(SF_RESOURCE_LIST_TYPE_ISOLATED, &rc2) << std::endl << std::endl;

        /**
        * Remove resource elements from blocked list
        */
        std::cout<< "OPERATION: SfRemoveElementFromList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_BLOCKED, &rc3); RESULT: "
            << sfc.sfRemoveElementFromList(SF_RESOURCE_LIST_TYPE_BLOCKED, &rc3) << std::endl << std::endl;

        /**
        * Get resource list
        */
        std::cout<< "GET RESOURCE LIST: " << std::endl << std::endl;

        std::cout<< "OPERATION: sfGetResourceList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_ISOLATED, &sfResourceList); RESULT: "
            << sfc.sfGetResourceList(SF_RESOURCE_LIST_TYPE_ISOLATED, &sfResourceList) << std::endl << std::endl;
        std::cout<< "OPERATION: sfGetResourceList(pSfControllerContext, SF_RESOURCE_LIST_TYPE_ISOLATED, &sfResourceList); RESULT: "
            << sfc.sfGetResourceList(SF_RESOURCE_LIST_TYPE_BLOCKED, &sfResourceList) << std::endl << std::endl;

        result = sfc.deininitialize();
    }

    return result;
}
