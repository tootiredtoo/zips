/**
****************************************************************************************************
* @file KernelModuleExample.c
* @example KernelModuleExample.c
* @brief This is an example of using kernel module [Security Filter Driver - SFD] API for filtering
*	of the system calls.
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created May 5, 2014 16:43
****************************************************************************************************
*/

#include <linux/init.h>
#include "sfd/SfdModuleInterface.h"

/**
****************************************************************************************************
* @brief Packet handler
* @param[in] pPacketInterface Packet header with packet type. This packet should be casted to 
* 	appropriate packet type
* @see SfdSysCallHandler
*
* @return SF_STATUS_OK on success,  SF_STATUS_FAIL otherwise, SF_STATUS_NOT_IMPLEMENTED in case if
*	handler of coresponding packet type is not implemented or not supported by this module
****************************************************************************************************
*/
asmlinkage SF_STATUS PacketHandler(const SfdPacketHeader* const pPacketInterface)
{
	SF_STATUS result = SF_STATUS_NOT_IMPLEMENTED;
	
	/*
	* This callback will be raised on corresponding system event will occurs.
	*/

	return result;
}

static SfdModuleInterface g_moduleInterface;

/**
****************************************************************************************************
* @brief Called when insmod executing. Allocate necessary resources and create user-kernel 
* intergfaces.
*
* @return Error code
****************************************************************************************************
*/
static int __init InitExampleModule(void)
{
	int result = 0;

	g_moduleInterface.moduleType = SFD_MODULE_TYPE_UEP;
	g_moduleInterface.PacketHandler = SfdUepPacketHandler;
	result = SfdRegisterModule(&g_moduleInterface);

	return -result;
}

/**
****************************************************************************************************
* @brief Called when rmmod executing. Free's all used resources.
*
* @return void
****************************************************************************************************
*/
static void __exit ExitExampleModule(void)
{
	SfdUnregisterModule(&g_moduleInterface);
}

/*
****************************************************************************************************
* MODULE OBLIGATORY DECLARATIONS
****************************************************************************************************
*/
module_init(InitExampleModule);
module_exit(ExitExampleModule);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maksym Koshel (m.koshel@samsung.com)");
MODULE_VERSION("v.0.0.1");
MODULE_DESCRIPTION("Example kernel module");
