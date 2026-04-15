/**
****************************************************************************************************
* @file SfCoreExample.c
* @example SfCoreExample.c
* @brief This is an example of how to use libcore library
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created May 13, 2014 16:43
****************************************************************************************************
*/

#include "libcore/SfCore.h"
#include "libcore/SfDebug.h"

/**
****************************************************************************************************
* @brief libcore example application entry point
* @param argc Amount of input arguments
* @param argv Pointer to the command line arguments
* @return Error code
****************************************************************************************************
*/
int main(int argc, char* argv[])
{
	SF_STATUS result = SF_STATUS_FAIL;

	result = SfOpenDebuggerContext(NULL);

	if (SF_SUCCESS(result))
	{
		SF_LOG_I("Information sample message!");
		SF_LOG_E("Error sample message!");
		SF_LOG_W("Warning sample message!");

		SF_LOG_I("Number of arguments: %d", argc);
		SF_LOG_I("Appliaction name: %s", argv[0]);

		result = SfCloseDebuggerContext(NULL);
	}

	return result;
}
