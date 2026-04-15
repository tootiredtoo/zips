##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(libcore C)

INCLUDE( FindPkgConfig )
pkg_check_modules( core_PKGS REQUIRED dlog glib-2.0 )

if(DEBUG_BUILD)
    ADD_DEFINITIONS(-DDEBUG_BUILD)
endif(DEBUG_BUILD)
##################################### PROJECT CMAKE SETUP END ######################################
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/internal/libcore/ ${core_PKGS_INCLUDE_DIRS})
FILE(GLOB SF_LIBCORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/source/*.c")
LIST(REMOVE_ITEM SF_LIBCORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/source/SfDebugWindows.c"
                                "${CMAKE_CURRENT_SOURCE_DIR}/source/SfMemoryKernel.c"
                                "${CMAKE_CURRENT_SOURCE_DIR}/source/SfFileKernel.c")
IF (CONSOLE_LOG)
  ADD_DEFINITIONS(-DUSE_CONSOLE_LOG)
  MESSAGE( "Kernel console log enabled" )
ELSE ()
  LIST(REMOVE_ITEM SF_LIBCORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/source/SfDebug.c")				
  MESSAGE( "Kernel console log disabled" )
ENDIF ()
			      

ADD_DEFINITIONS(-DUS_MODULE -DSF_BIN_TAG=\"${PROJECT_NAME}\")
ADD_LIBRARY(core SHARED ${SF_LIBCORE_SRC})
TARGET_LINK_LIBRARIES(core ${core_PKGS_LIBRARIES})
INSTALL( TARGETS core LIBRARY DESTINATION ${LIB_INSTALL_DIR} )
