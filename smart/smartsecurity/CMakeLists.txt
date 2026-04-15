##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(smartsecurity2)
##################################### PROJECT CMAKE SETUP END ######################################
SET( CONSOLE_LOG                OFF  CACHE BOOL "Enable print to kernel log" )
SET( SMARTSECURITY_CONTROLLER   OFF CACHE BOOL "Build smartsecurity manager UI")
if(DEBUG_BUILD)
        ADD_DEFINITIONS(-g -DDEBUG_BUILD)
endif(DEBUG_BUILD)

##################################### DEFINE ARCH START ############################################
if(ARCH_ARM OR CMAKE_SYSTEM_PROCESSOR STREQUAL armv7l OR CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64)
    MESSAGE( "-- arm build" )
    SET(ARCH_ARM TRUE)
    SET( SF_THIRD_PARTY_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/third_party/armv7l)

elseif(ARCH_X86_64)
    MESSAGE( "-- x86_64 build" )
    SET( SF_THIRD_PARTY_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/third_party/x86_64)

elseif(ARCH_X86)
    MESSAGE( "-- x86 build" )
    SET( SF_THIRD_PARTY_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/third_party/i586)

endif(ARCH_ARM OR CMAKE_SYSTEM_PROCESSOR STREQUAL armv7l OR CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64)
##################################### DEFINE ARCH END ##############################################

################################ Add to the build schedule START ###################################
IF(SMARTSECURITY_CONTROLLER)
  ADD_SUBDIRECTORY(po)
ENDIF()
ADD_SUBDIRECTORY(source)
IF(DEFINED TOMATO)
    ADD_SUBDIRECTORY(tomato/tc)
ENDIF(DEFINED TOMATO)
################################# Add to the build schedule END ####################################

IF(NOT DEFINED MANIFESTDIR)
    SET(MANIFESTDIR "${TZ_SYS_RO_SHARE}/packages")
ENDIF(NOT DEFINED MANIFESTDIR)

IF(SMARTSECURITY_CONTROLLER)
  INSTALL(FILES org.tizen.smart_security.xml DESTINATION ${MANIFESTDIR})
  CONFIGURE_FILE(org.tizen.smart_security.xml.in org.tizen.smart_security.xml)
ENDIF()
