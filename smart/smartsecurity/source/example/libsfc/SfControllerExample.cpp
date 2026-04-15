
#include "libcore/SfDebug.h"

#include "libsfc/SfComponent.h"
#include "libsfc/SfResource.h"

int main(int argc, char* argv[])
{
	SF_STATUS result = SF_STATUS_FAIL;

	result = SfOpenDebuggerContext(NULL);

	if (SF_SUCCESS(result))
	{
		// Get instance to the Framework configuration
		SfControllerContext* pSfControllerContext = SfCreateControllerContext();
		result = SfOpenControllerContext(pSfControllerContext, (Char*) "UI App", 0xbedabeda);

		if (SF_SUCCESS(result))
		{
			SF_LOG_I("Successfull opened");

			result = SfCloseControllerContext(pSfControllerContext);
			
			result = SfDestroyControllerContext(pSfControllerContext);
		}
		else
		{
			SF_LOG_I("Can't open Controller context!");
		}

		result = SfCloseDebuggerContext(NULL);
	}

	SF_LOG_I("Argument list: ");
	for (int i = 0; i < argc; i++)
	{
		SF_LOG_I("%d: %s", i, argv[i]);
	}

	return result;
}