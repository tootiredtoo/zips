/**
****************************************************************************************************
* @vd_noapi
* @file SfSettings.h
* @brief Security framework [SF] tags for tasks
* @author Maksym Koshel (m.koshel@samsung.com)
* @date Created Sep 22, 2014
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_SETTINGS_H_
#define _SF_SETTINGS_H_

#include <tzplatform_config.h>

/**
****************************************************************************************************
* @def SF_CONTROLLER_LOCATION
* @brief Controller application location
****************************************************************************************************
*/
#define SF_CONTROLLER_LOCATION tzplatform_mkpath(TZ_SYS_RO_APP, "org.tizen.smart_security")

/**
****************************************************************************************************
* @def SF_INFO_ICON_SMARTSECURITY
* @brief info_icon_smartsecurity.png location
****************************************************************************************************
*/
#define SF_INFO_ICON_DIR tzplatform_mkpath(TZ_SYS_RO_APP, "com.samsung.tv.theme-resource/shared/res/org.tizen.smart_security")

/**
****************************************************************************************************
* @def SF_SFPMD_FILESCAN_CONFIG
* @brief filescan.json location
****************************************************************************************************
*/
#define SF_SFPMD_FILESCAN_CONFIG tzplatform_mkpath(TZ_SYS_RO_APP, "org.tizen.smart_security/config/filescan.json")

/**
****************************************************************************************************
* @def SF_FIREWALL_DEFAULT_RULES
* @brief firewall_default_rules.json location
****************************************************************************************************
*/
#define SF_FIREWALL_DEFAULT_RULES tzplatform_mkpath(TZ_SYS_RO_APP, "org.tizen.smart_security/config/firewall_default_rules.json")

/**
****************************************************************************************************
* @def SF_INFO_ICON_SMARTSECURITY
* @brief progress_bar.png location
****************************************************************************************************
*/
//#define SF_PROGRESS_BAR_ICON SF_CONTROLLER_LOCATION "/shared/images/progress_bar.png"

/**
****************************************************************************************************
* @def SF_SCAN_RUNNING_EDJ
* @brief scan_running.edj location
****************************************************************************************************
*/
//#define SF_SCAN_RUNNING_EDJ SF_CONTROLLER_LOCATION "/shared/edje/scan_running.edj"

/**
****************************************************************************************************
* @def SF_SFPMD_BLOCKED_RESOURCES
* @brief blocked_resources.json location
****************************************************************************************************
*/
#define SF_SFPMD_BLOCKED_RESOURCES tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/shared/blocked_resources.json") 

/**
****************************************************************************************************
* @def SF_SMARTSECURITY_PACKAGE_LOCALE
* @brief Smart Security product localization data
****************************************************************************************************
*/
#define SF_SMARTSECURITY_PACKAGE_LOCALE tzplatform_mkpath(TZ_SYS_RO_APP, "org.tizen.smart_security/shared/locale")

/**
****************************************************************************************************
* @def SF_CONTROLLER_PACKAGE
* @brief Controller application package name
****************************************************************************************************
*/
#define SF_CONTROLLER_PACKAGE               "smart_security"

/**
****************************************************************************************************
* @def SF_CONTROLLER_WINDOW_PARAMETER
* @brief Controller window name paramter
****************************************************************************************************
*/
#define SF_CONTROLLER_WINDOW_PARAMETER      "wnd"

/**
****************************************************************************************************
* @def SF_CONTROLLER_WINDOW_ID_PARAMETER
* @brief Controller window ID parameter
****************************************************************************************************
*/
#define SF_CONTROLLER_WINDOW_ID_PARAMETER   "id"


#define SF_CONTROLLER_WINDOW_VALUE_PARAMETER   "value"

/**
****************************************************************************************************
* @def SF_SETTING_BASE
* @brief Base path to the VCONF options of the Smart Security
****************************************************************************************************
*/
#define SF_SETTING_BASE                     "db/menu/system/smart-security"

/**
****************************************************************************************************
* @def SF_SETTINGS_SUBPATH
* @brief Settings sub-path to the VCONF options of the Smart Security
****************************************************************************************************
*/
#define SF_SETTING_SUBPATH                  "/settings"

/**
****************************************************************************************************
* @def SF_SMART_SECURITY_SETTING
* @brief Smart Security setting
****************************************************************************************************
*/
#define SF_SMART_SECURITY_SETTING           SF_SETTING_BASE "/smart-security"

/**
****************************************************************************************************
* @def SF_SCAN_SETTING
* @brief Scan setting of smart security
****************************************************************************************************
*/
#define SF_SCAN_SETTING                     SF_SETTING_BASE "/scan"

/**
****************************************************************************************************
* @def SF_ISOLATED_LIST_SETTING
* @brief Isolated list setting of smart security
****************************************************************************************************
*/
#define SF_ISOLATED_LIST_SETTING            SF_SETTING_BASE "/isolated-list"

/**
****************************************************************************************************
* @def SF_BLOCKED_LIST_SETTING
* @brief Blocked list setting of smart setting
****************************************************************************************************
*/
#define SF_BLOCKED_LIST_SETTING             SF_SETTING_BASE "/blocked-list"

/**
****************************************************************************************************
* @def SF_SETTINGS_SETTING
* @brief Settings setting of smart secrity
****************************************************************************************************
*/
#define SF_SETTINGS_SETTING                 SF_SETTING_BASE SF_SETTING_SUBPATH

/**
****************************************************************************************************
* @def SF_AUTO_FILESEND_FLAG
* @brief Antivirus setting
****************************************************************************************************
*/
#define SF_AUTO_FILESEND_FLAG               SF_SETTING_BASE SF_SETTING_SUBPATH "/anti-virus"

/**
****************************************************************************************************
* @def SF_ANTI_VIRUS_PROCESS
* @brief Anti-Virus Process Name
****************************************************************************************************
*/
#define SF_ANTI_VIRUS_PROCESS               "ANTIVIRUS"
/**
****************************************************************************************************
* @def SF_FIREWALL_PROCESS
* @brief FireWall Process Name
****************************************************************************************************
*/
#define SF_FIREWALL_PROCESS                 "FIREWALL"


/**
****************************************************************************************************
* @def SF_DATA_LOG_PATH
* @brief Smart Security Data Log file path
****************************************************************************************************
*/
#define SF_DATA_LOG_PATH tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/data/report/")

/**
****************************************************************************************************
* @enum SF_OPTION_TYPE
* @brief Option type (index) enumeration
****************************************************************************************************
*/
typedef enum
{
    SF_SETTING_TYPE_UNKNOWN = 0, ///< Unknown setting index
    SF_SETTING_TYPE_ANTIVIRUS, ///< Antivirus setting index
    /**
    * @warning This enumeration related with 's_optionConfigDictionary' array. Please,
    *   be carefull modifying it.
    */

} SF_SETTING_TYPE;

/**
****************************************************************************************************
* @enum SF_SETTING_VALUE
* @brief Type definition of the setting item value
****************************************************************************************************
*/
typedef enum
{
    SF_SETTING_VALUE_OFF = 0, ///< Setting disabled
    SF_SETTING_VALUE_ON = 1, ///< Setting enabled
    SF_SETTING_VALUE_MAX
} SF_SETTING_VALUE;

/**
****************************************************************************************************
* @enum SF_WINDOW_TYPE
* @brief Window type selecet by user in System Menu
****************************************************************************************************
*/
typedef enum
{
    SF_WINDOW_TYPE_UNKNOWN = 0, ///< Unknown window
    SF_WINDOW_TYPE_SCAN = 1, ///< Scan window
    SF_WINDOW_TYPE_ISOLATED_LIST = 2, ///< Isolated window
    SF_WINDOW_TYPE_BLOCKED_LIST = 3, ///< Blocked window
    SF_WINDOW_TYPE_SCAN_RESULT_NOTI = 4, ///< Scan Result Window on notification

    /**
    * @warning This enumeration related with resource json files. Please, be carefull modifying it.
    */
    SF_WINDOW_TYPE_MSGBOX = 5,
    SF_WINDOW_TYPE_GLOBAL_NOTI = 6,
    SF_WINDOW_TYPE_BLOCKED_LIST_NOTI = 7,
    SF_WINDOW_TYPE_REPORT_NOTI = 8,
    SF_WINDOW_TYPE_MAX
} SF_WINDOW_TYPE;
/**
****************************************************************************************************
* @struct SfBundleWindow
* @brief                    Bundle Value for Each windows
****************************************************************************************************
*/
typedef struct
{
    char* Type;
    char* Id;
} SfBundleWindow;
/**
****************************************************************************************************
* @brief Static configuration of Window Bundle Value
****************************************************************************************************
*/
static const SfBundleWindow BundleWin[ SF_WINDOW_TYPE_MAX ]=
{
    { "Unknown",            "0"},
    { "Scan",               "1"},
    { "Isolated List",      "2"},
    { "Blocked List",       "3"},
    { "ScanResult List",    "4"},
    { "msgsbox",            "5"},
    { "GlobalNoti",         "6"},
    { "BlockedListNoti",    "7"},
    { "ReportMsgBox",       "8"}
};
/**
****************************************************************************************************
* @struct SfOptionConfig
* @brief Option configuration structure
* @note This structure used for identifying settings in the VCONF DB
****************************************************************************************************
*/
typedef struct
{
    SF_SETTING_TYPE type; ///< Option type
    char* optionName; ///< Option name
} SfSettingConfig;

/**
****************************************************************************************************
* @brief Static configuration of the VCONF options
****************************************************************************************************
*/
static const SfSettingConfig s_optionConfigDictionary[] =
{
    {SF_SETTING_TYPE_UNKNOWN,       "NULL"},
    {SF_SETTING_TYPE_ANTIVIRUS,     SF_AUTO_FILESEND_FLAG},
};

/**
****************************************************************************************************
* @brief Size of s_optionConfigDictionary
****************************************************************************************************
*/
static const Uint s_dictionaryOptionCount =
        sizeof(s_optionConfigDictionary) / sizeof(s_optionConfigDictionary[0]);

/**
****************************************************************************************************
* @def SF_SETTING_ITEM_NAME_LENGH
* @brief Defines name size of the setting item
****************************************************************************************************
*/
#define SF_SETTING_ITEM_NAME_LENGH  255

/**
****************************************************************************************************
* @struct SfSettingItem
* @brief Setting item structure
****************************************************************************************************
*/
typedef struct
{
    char name[SF_SETTING_ITEM_NAME_LENGH];
    SF_SETTING_VALUE value;

} SfSettingItem;

#endif /* !_SF_SETTINGS_H_ */
