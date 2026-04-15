/**
****************************************************************************************************
* @file SfcAccess.h
* @brief Security framework [SF] controller access class
* @author Sergey Leonov (se.leonov@samsung.com)
* @date Created Jul 30, 2014 15:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SFC_ACCESS_H_
#define _SFC_ACCESS_H_

#include <iostream>
#include <list>

#include "libcore/SfDebug.h"

#include "libsfc/SfComponent.h"
#include "libsfc/SfResource.h"

/**
***************************************************************************************************
*
***************************************************************************************************
*/
class SfController
{

private:
    SfControllerContext* m_pSfControllerContext;

    std::list<SfComponent*>  sfComponentList;
    std::list<SfComponent*>::iterator sfcIterator;

    std::list<SfResource*>  sfResourceListIsolated;
    std::list<SfResource*>::iterator sfResourceListIsolatedIterator;

    std::list<SfResource*>  sfResourceListBlocked;
    std::list<SfResource*>::iterator sfResourceListBlockedIterator;

public:
    SfController();
    ~SfController();

    SF_STATUS initialize();
    SF_STATUS deininitialize();

    SF_STATUS sfRegisterComponent(SfComponent* const pComponent);
    SF_STATUS sfUnregisterComponent(SfComponent* const pComponent);
    SF_STATUS sfSetComponentState(SfComponent* const pComponent, SF_COMPONENT_STATE newState);
    SF_STATUS sfGetComponentState(SfComponent* const pComponent, SF_COMPONENT_STATE* const pCurrentState);

    SF_STATUS sfGetResourceList(const SF_RESOURCE_LIST_TYPE listType, SfResourceList* const pList);
    SF_STATUS sfAddElementToList(const SF_RESOURCE_LIST_TYPE listType, SfResource* const pResource);
    SF_STATUS sfRemoveElementFromList(SF_RESOURCE_LIST_TYPE listType, SfResource* const pResource);

    void showComponentList();
    void showResourceListIsolated();
    void showResourceListBlocked();

}; // class SfcAccess

#endif /* _SFC_ACCESS_H_ */

