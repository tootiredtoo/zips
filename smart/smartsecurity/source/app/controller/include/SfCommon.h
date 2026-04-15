#ifndef _SF_COMMON_H_
#define _SF_COMMON_H_

#include "SfEflIncludes.h"
#include "libcore/SfCore.h"
#include "libprimitive/SfFs.h"

#include <vector>
#include <string>

// window opacity
#define OPACITY 240

#define SF_UI_ROTATION_SCALE 0.5625*2
#define VCONF_DISPLAY_ORIENTATION "db/menu/onscreendisplay/display_orientation/onscreen_menu_orientation"
#define SF_MENU_PACKAGE_NAME "org.tizen.menu"
#define SF_JOB_REQUESTER_NAME "smartsecurity_ui"
#define TIMEOUT_UI 10*60*1.0

struct ListViewItem
{
    std::string         path;
    std::string         name;
    bool                status;
    bool                need_del;
    Elm_Object_Item*    pItem;
    Evas_Object*        pCheckBox;

    ListViewItem()
        : path()
        , name()
        , status( false )
        , need_del( false )
        , pItem( NULL )
        , pCheckBox( NULL )
    {
    }
};

typedef std::vector< ListViewItem >         ListViewItemVector;

typedef enum 
{
    SF_WORKER_REQUEST_ITEM_REMOVE = 0,
    SF_WORKER_REQUEST_ITEM_FOCUS = 1,
    SF_WORKER_REQUEST_FINISH = 2,
    SF_WORKER_REQUEST_MAX
} SF_WORKER_REQUEST;

typedef struct SfPassData
{
    SF_WORKER_REQUEST request;
    int status;
    void* pObject;
} SfWorkerPassData;

typedef enum
{
    SF_WINDOW_STATE_UNINITIALIZED = 0, ///< Window state invisible
    SF_WINDOW_STATE_INITIALIZED = 1 ///< Window state visible
} SF_WINDOW_STATE;

typedef struct
{
    void* pContext;
    void* pParam;
}MessageBoxButtonUserParam;

typedef struct
{
    MessageBoxButtonUserParam* pUserParam;
    void* pSfMessageBox;
}MessageBoxButtonCbParam;

#endif  // _SF_COMMON_H_