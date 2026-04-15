##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(sfpmd CXX)
###################################### PROJECT CMAKE SETUP END #####################################
SET( BUILD_PLUGIN                ON  CACHE BOOL "Build common daemon plugin instead of sfpmd service" )

SET(REQUIRES 
    dlog
    vconf
    sid
    jsoncpp
    capi-appfw-application
    deviced
    capi-network-connection
    capi-system-usbdevice)

if(${IS_TIZEN_LITE} STREQUAL "y")
    MESSAGE(STATUS "[BUILD LICENSING]")
    ADD_DEFINITIONS("-DLICENSING_PRODUCT")
else(${IS_TIZEN_LITE} STREQUAL "y")
    MESSAGE(STATUS "[BUILD SAMSUNG]")
    ADD_DEFINITIONS("-DSAMSUNG_PRODUCT")
    SET(REQUIRES ${REQUIRES} smart-deadlock scs-common-client)
endif(${IS_TIZEN_LITE} STREQUAL "y")
  
IF(${SHOW_SMARTSECURITY_POPUP} STREQUAL "y")
  LIST(APPEND REQUIRES notification)
ENDIF()

include( FindPkgConfig )
pkg_check_modules( SFPMD_PKGS REQUIRED ${REQUIRES} )

if(DEBUG_BUILD)
    ADD_DEFINITIONS(-DDEBUG_BUILD)
endif(DEBUG_BUILD)

IF( ${THEWALL_SUPPORT} STREQUAL "Y" )
    MESSAGE(STATUS "BUILD FOR THE WALL")
    ADD_DEFINITIONS(-DTHEWALL_SUPPORT)
ENDIF( ${THEWALL_SUPPORT} STREQUAL "Y" )

IF( ${SHOW_SMARTSECURITY_POPUP} STREQUAL "Y" )
    MESSAGE(STATUS "BUILD FOR SHOW_SMARTSECURITY_POPUP")
    ADD_DEFINITIONS(-DSHOW_SMARTSECURITY_POPUP)
ENDIF( ${SHOW_SMARTSECURITY_POPUP} STREQUAL "Y" )

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/internal ${CMAKE_CURRENT_SOURCE_DIR}/include/ ${aul_INCLUDE_DIRS})
INCLUDE_DIRECTORIES(${SFPMD_PKGS_INCLUDE_DIRS})

IF (CONSOLE_LOG)
  ADD_DEFINITIONS(-DUSE_CONSOLE_LOG)
ENDIF()

IF (BUILD_PLUGIN)
  ADD_DEFINITIONS(-DUSE_PLUGIN)
ENDIF()

# Output to log caller and description
ADD_DEFINITIONS(-DDEBUG_REPORT)

ADD_DEFINITIONS(-DUS_MODULE -DSF_BIN_TAG=\"${PROJECT_NAME}\")
FILE( GLOB_RECURSE SFPMD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp" )
LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/cmake/ ${SF_THIRD_PARTY_LIB_DIR} )

IF (BUILD_PLUGIN)
  # Remove SfKUEPSwitcher.cpp for plugin
  SET(FILE_TO_REMOVE "${CMAKE_CURRENT_SOURCE_DIR}/source/SfKUEPSwitcher.cpp")
  list(REMOVE_ITEM SFPMD_SRC "${FILE_TO_REMOVE}")
  ADD_LIBRARY(sfpmd-plugin SHARED ${SFPMD_SRC})
  TARGET_LINK_LIBRARIES(sfpmd-plugin core primitive pthread dl sfkc ${SFPMD_PKGS_LDFLAGS})
ELSE()
  ADD_EXECUTABLE(sfpmd ${SFPMD_SRC})
  TARGET_LINK_LIBRARIES(sfpmd core primitive pthread dl sfkc ${SFPMD_PKGS_LDFLAGS}) 
ENDIF()

IF(BUILD_TESTS)
SET(
    SFPMD_SRC_FOR_UT 
    ${CMAKE_SOURCE_DIR}/source/app/sfpmd/source/SfKUEPSwitcher.cpp
    ${CMAKE_SOURCE_DIR}/source/app/sfpmd/source/SfRecorder.cpp
    ${CMAKE_SOURCE_DIR}/source/app/sfpmd/source/SfTaskMessageReceiver.cpp
)

MESSAGE (sfpmd_forut_source : "${SFPMD_SRC_FOR_UT}")

add_library(sfpmdTest STATIC ${SFPMD_SRC_FOR_UT})
TARGET_LINK_LIBRARIES(sfpmdTest core primitive pthread dl sfkc 
                      ${appcore-common_LIBRARIES} ${aul_LIBRARIES} ${SFPMD_PKGS_LDFLAGS})
ENDIF()

IF (BUILD_PLUGIN)
  SET(PLUGIN_DIR "/usr/share/security-solution-daemon/plugins")
  INSTALL( TARGETS sfpmd-plugin LIBRARY DESTINATION ${PLUGIN_DIR} )
  
ELSE()
  configure_file(sfpmd.service.in sfpmd.service  @ONLY)

  INSTALL( TARGETS sfpmd RUNTIME DESTINATION ${TZ_SYS_BIN} )
ENDIF()
