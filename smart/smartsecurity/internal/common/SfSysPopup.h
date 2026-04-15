/**
****************************************************************************************************
* @vd_noapi
* @file SfSysPopup.h
* @brief Security framework [SF] class for System popup
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Sep 24, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
#ifndef _SF_SYSPOPUP_H_
#define _SF_SYSPOPUP_H_

#include "libcore/SfCore.h"
#include <bundle.h>
#include <bundle_internal.h>
#include <syspopup_caller.h>

class SfSysPopup
{
public:
	SfSysPopup()
	{
		if( service_create( &svcHandler ) != 0 )
		{
			SF_LOG_E("service_create Error");
		}
	};
	~SfSysPopup()
	{
		if( !svcHandler )
		{
			service_destory(svcHandler);
			svcHandler = NULL;
		}
	}

private:
	service_h svcHandler;
};

#endif /* _SF_SYSPOPUP_H_ */