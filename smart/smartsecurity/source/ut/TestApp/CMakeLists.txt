####################################################################################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(SfTestApp CXX)
###################################################################################################
INCLUDE( FindPkgConfig )
SET( TEST_APP_REQUIRED
  dlog
  gtest
  gmock
  libnl-3.0
)

IF(${SHOW_SMARTSECURITY_POPUP} STREQUAL "y")
  LIST(APPEND TEST_APP_REQUIRED notification)
ENDIF()
pkg_check_modules( TestApp_PKGS REQUIRED ${TEST_APP_REQUIRED} )

ADD_DEFINITIONS( -DDEBUG_BUILD -DUS_MODULE -DSF_TRANSPORT_NETLINK )
ADD_DEFINITIONS( -Wall -Wextra )
ADD_DEFINITIONS(-DTZ_SYS_LIB="${TZ_SYS_LIB}")

INCLUDE_DIRECTORIES( ${CMAKE_SOURCE_DIR}/internal
                     ${CMAKE_SOURCE_DIR}/source/lib/
                     ${CMAKE_SOURCE_DIR}/source/app/sfpmd/include
                     ${TestApp_PKGS_INCLUDE_DIRS})

FILE( GLOB_RECURSE TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../lib/libcore/*.cpp"
                            "${CMAKE_CURRENT_SOURCE_DIR}/../lib/libprimitive/*.cpp"
                            "${CMAKE_CURRENT_SOURCE_DIR}/../lib/libsfkc/*.cpp"
                            "${CMAKE_CURRENT_SOURCE_DIR}/../lib/libtransport/*.cpp"
                            "${CMAKE_CURRENT_SOURCE_DIR}/../sfd/reporter/*.cpp" 
                            )
LIST( APPEND TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../main.cpp" )
# LINK_DIRECTORIES( ${CMAKE_SOURCE_DIR}/lib/cmake/ ${TestApp_PKGS_LIBRARIES})

ADD_EXECUTABLE( SfTestApp ${TEST_SRC} )
TARGET_LINK_LIBRARIES( SfTestApp primitive transport core sfkc ${TestApp_PKGS_LDFLAGS} sfpmdTest)
INSTALL( TARGETS SfTestApp RUNTIME DESTINATION ${TZ_SYS_BIN}/UT )
