##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(libsfkc CXX)
##################################### PROJECT CMAKE SETUP END ######################################
INCLUDE( FindPkgConfig )
pkg_check_modules( dlog REQUIRED dlog )
pkg_check_modules( libnl-3.0 REQUIRED libnl-3.0 )

SET(SF_LIBSFKC_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/source/")
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/internal ${CMAKE_SOURCE_DIR}/internal/libsfkc/
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/ ${CMAKE_SOURCE_DIR} ${dlog_INCLUDE_DIRS}
                    ${libnl-3.0_INCLUDE_DIRS})

FILE(GLOB_RECURSE SF_LIBSFKC_SRC "${SF_LIBSFKC_SRC_DIR}/*.cpp")
ADD_DEFINITIONS(-DUS_MODULE -DSF_TRANSPORT_NETLINK -DSF_BIN_TAG=\"${PROJECT_NAME}\")
ADD_LIBRARY(sfkc SHARED ${SF_LIBSFKC_SRC})
TARGET_LINK_LIBRARIES(sfkc core protocol transport ${libnl-3.0_LIBRARIES})
INSTALL( TARGETS sfkc LIBRARY DESTINATION ${LIB_INSTALL_DIR})
