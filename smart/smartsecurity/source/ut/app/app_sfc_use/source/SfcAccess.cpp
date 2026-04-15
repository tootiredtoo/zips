/**
****************************************************************************************************
* @file SfcAccess.cpp
* @brief Security framework [SF] controller access methods implementation
* @author Sergey Leonov (se.leonov@samsung.com)
* @date Created Jul 30, 2014 15:47
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
SfController::SfController()
{
}

/**
***************************************************************************************************
*
***************************************************************************************************
*/
SfController::~SfController()
{
}

/**
***************************************************************************************************
//@sut      initialize
//@brief    Initalize SmartSecurity UI
***************************************************************************************************
*/
SF_STATUS SfController::initialize()
{
    SF_STATUS result = SF_STATUS_FAIL;
    result = SfOpenDebuggerContext( NULL );

    if ( SF_SUCCESS(result) )
    {
        // Get instance to the Framework configuration
        m_pSfControllerContext = SfCreateControllerContext();
        result = SfOpenControllerContext( m_pSfControllerContext, (Char*) "UI App", 0xbedabeda );
    }

    return result;
}

/**
***************************************************************************************************
//@sut      deininitialize
//@brief    Destory SmartSecurity UI
***************************************************************************************************
*/
SF_STATUS SfController::deininitialize()
{
    SF_STATUS result = SF_STATUS_FAIL;

    result = SfCloseControllerContext( m_pSfControllerContext );
    result = SfDestroyControllerContext( m_pSfControllerContext );
    result = SfCloseDebuggerContext( NULL );
    return result;
}

/**
****************************************************************************************************
//@sut      sfRegisterComponent
//@brief    Register SmartSecurity each component
****************************************************************************************************
*/
SF_STATUS SfController::sfRegisterComponent(SfComponent* const pComponent)
{
    sfComponentList.push_back(pComponent);

    return SfRegisterComponent(m_pSfControllerContext, pComponent);
}

/**
****************************************************************************************************
//@sut      sfUnregisterComponent
//@brief    Register SmartSecurity each component
****************************************************************************************************
*/
SF_STATUS SfController::sfUnregisterComponent(SfComponent* const pComponent)
{
    sfComponentList.remove(pComponent);

    return SfUnregisterComponent(m_pSfControllerContext, pComponent);
}

/**
***************************************************************************************************
//@sut      sfSetComponentState
//@brief    Set SmartSecurity each component state
//@input    SfComponent : component SF_COMPONENT_STATE : state
***************************************************************************************************
*/
SF_STATUS SfController::sfSetComponentState(SfComponent* const pComponent,
                                            SF_COMPONENT_STATE newState)
{
    return SfSetComponentState(m_pSfControllerContext, pComponent, newState);
}

/**
***************************************************************************************************
//@sut      sfGetComponentState
//@brief    Get SmartSecurity each component state
//@input    SfComponent : component SF_COMPONENT_STATE : state
***************************************************************************************************
*/
SF_STATUS SfController::sfGetComponentState(SfComponent* const pComponent,
                                            SF_COMPONENT_STATE* const pCurrentState)
{
    return SfGetComponentState(m_pSfControllerContext, pComponent, pCurrentState);
}

/**
***************************************************************************************************
//@sut      sfGetResourceList
//@brief    Get Isolated List
//@input    SF_RESOURCE_LIST_TYPE : list type  SfResourceList : List
***************************************************************************************************
*/
SF_STATUS SfController::sfGetResourceList(const SF_RESOURCE_LIST_TYPE listType,
                                          SfResourceList* const pList)
{
    if ( SF_RESOURCE_LIST_TYPE_ISOLATED == listType)
    {
        showResourceListIsolated();
    }
    else if ( SF_RESOURCE_LIST_TYPE_BLOCKED == listType)
    {
        showResourceListBlocked();
    }

    return SfGetResourceList(m_pSfControllerContext, listType, pList);
}

/**
***************************************************************************************************
//@sut      sfAddElementToList
//@brief    Isolate files
//@input    SF_RESOURCE_LIST_TYPE : list type  SfResourceList : List
***************************************************************************************************
*/
SF_STATUS SfController::sfAddElementToList(const SF_RESOURCE_LIST_TYPE listType,
                                           SfResource* const pResource)
{
    if ( SF_RESOURCE_LIST_TYPE_ISOLATED == listType)
    {
        sfResourceListIsolated.push_back(pResource);
    }
    else if ( SF_RESOURCE_LIST_TYPE_BLOCKED == listType)
    {
        sfResourceListBlocked.push_back(pResource);
    }

    return SfAddElementToList(m_pSfControllerContext, listType, pResource);
}

/**
***************************************************************************************************
//@sut      sfRemoveElementFromList
//@brief    Recover file
//@input    SF_RESOURCE_LIST_TYPE : list type  SfResourceList : List
***************************************************************************************************
*/
SF_STATUS SfController::sfRemoveElementFromList(SF_RESOURCE_LIST_TYPE listType,
                                                SfResource* const pResource)
{
    if ( SF_RESOURCE_LIST_TYPE_ISOLATED == listType)
    {
        sfResourceListIsolated.remove(pResource);
    }
    else if ( SF_RESOURCE_LIST_TYPE_BLOCKED == listType)
    {
        sfResourceListBlocked.remove(pResource);
    }

    return SfRemoveElementFromList(m_pSfControllerContext, listType, pResource);
}

/**
***************************************************************************************************
//@sut      showComponentList
//@brief    Show ComponentList
***************************************************************************************************
*/
void SfController::showComponentList()
{
    for (sfcIterator = sfComponentList.begin(); sfcIterator != sfComponentList.end(); ++sfcIterator)
    {
        std::cout<< "type: " << (*sfcIterator)->type << "; ";
        std::cout<< "componentPath: " << (*sfcIterator)->componentPath << "; ";
        std::cout<< "componentEnvironment: ";

        if( (*sfcIterator)->componentEnvironment == NULL )
            std::cout<< "NULL;";
        else
            std::cout<< (*sfcIterator)->componentEnvironment << ";";

        std::cout << std::endl << std::endl;
    }
}

/**
***************************************************************************************************
//@sut      showResourceListIsolated
//@brief    Show Isolated List
***************************************************************************************************
*/
void SfController::showResourceListIsolated()
{
    for (sfResourceListIsolatedIterator = sfResourceListIsolated.begin();
         sfResourceListIsolatedIterator != sfResourceListIsolated.end(); ++sfResourceListIsolatedIterator)
    {
        std::cout<< "resourceType: " << (*sfResourceListIsolatedIterator)->resourceType << "; ";
        std::cout<< "resourceName: " << (*sfResourceListIsolatedIterator)->resourceName <<'\n';
    }
}

/**
***************************************************************************************************
//@sut      showResourceListBlocked
//@brief    show blocked List
***************************************************************************************************
*/
void SfController::showResourceListBlocked()
{
    for (sfResourceListBlockedIterator = sfResourceListBlocked.begin();
         sfResourceListBlockedIterator != sfResourceListBlocked.end(); ++sfResourceListBlockedIterator)
    {
        std::cout<< "resourceType: " << (*sfResourceListBlockedIterator)->resourceType << "; ";
        std::cout<< "resourceName: " << (*sfResourceListBlockedIterator)->resourceName <<'\n';
    }
}
