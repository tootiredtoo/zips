##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(libprimitive CXX)
##################################### PROJECT CMAKE SETUP END ######################################
INCLUDE( FindPkgConfig )
pkg_check_modules( dlog REQUIRED dlog )

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/internal ${CMAKE_SOURCE_DIR}/internal/libprimitive
                    ${dlog_INCLUDE_DIRS})
FILE(GLOB SF_LIBPRIMITIVE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

ADD_DEFINITIONS(-DUS_MODULE -DSF_BIN_TAG=\"${PROJECT_NAME}\")
ADD_LIBRARY(primitive SHARED ${SF_LIBPRIMITIVE_SRC})
LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/cmake/)
TARGET_LINK_LIBRARIES(primitive core pthread)
INSTALL( TARGETS primitive LIBRARY DESTINATION ${LIB_INSTALL_DIR} )
