CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(smart_security C CXX)

SET(VERSION 0.1.0)

INCLUDE(FindPkgConfig)
IF(NOAUDIO)
pkg_check_modules(PKGS REQUIRED elementary dlog vconf ui-gadget-1 aul vd-win-util menu-plugin-loader
                  jsoncpp uifw_misc efl-assist capi-system-usbdevice notification voice-control-elm capi-ui-efl-util)
ELSE()
pkg_check_modules(PKGS REQUIRED elementary dlog vconf ui-gadget-1 aul vd-win-util menu-plugin-loader
                  jsoncpp uifw_misc efl-assist capi-system-usbdevice notification capi-ui-efl-util)
ENDIF(NOAUDIO)
		  
SET(CMAKE_INSTALL_PREFIX "${TZ_SYS_RO_APP}/org.tizen.smart_security")

IF(NOT DEFINED PACKAGE_NAME)
	SET(PACKAGE_NAME "org.tizen.${PROJECT_NAME}")
ENDIF(NOT DEFINED PACKAGE_NAME)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})

IF(NOT DEFINED BINDIR)
	SET(BINDIR "${SF_CONTROLLER_PREFIX}/bin")
ENDIF(NOT DEFINED BINDIR)

ADD_DEFINITIONS("-DLOG_TAG=\"${PROJECT_NAME}\"")
ADD_DEFINITIONS("-DPACKAGE=\"${PACKAGE_NAME}\"")
ADD_DEFINITIONS("-DPROVIDERDIR=\"${PROVIDERDIR}\"")
ADD_DEFINITIONS(-DNO_AUDIO=${NOAUDIO})

#Added by Maksym Koshel (m.koshel@samsung.com) temporary changes
ADD_DEFINITIONS(-DDEBUG_BUILD -DUS_MODULE -pthread -DSF_BIN_TAG=\"${PROJECT_NAME}\")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)

#Added by Maksym Koshel (m.koshel@samsung.com)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/internal ${CMAKE_SOURCE_DIR} ${jsoncpp_INCLUDE_DIRS} ${efl-assist_INCLUDE_DIRS})

FILE( GLOB_RECURSE SRCS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp" )
ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})

FOREACH(flag ${PKGS_CFLAGS})
	SET(EXTRA_CFLGAS "${EXTRA_CFLGAS} ${flag}")
ENDFOREACH(flag)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLGAS} -fPIE")

FOREACH(flag ${PKGS_CFLAGS})
	SET(EXTRA_CXXFLGAS "${EXTRA_CFLGAS} ${flag}")
ENDFOREACH(flag)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_CXXFLGAS} -fPIE")

SET(CMAKE_EXE_LINKER_FLAGS "-pie")

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${PKGS_LDFLAGS} primitive core dl ${jsoncpp_LIBRARIES} ${fl-assist_LIBRARIES} )

# Install
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)

# For uifw_misc package
SET(UIFW_MISC_FLAGS "-luifw_misc")