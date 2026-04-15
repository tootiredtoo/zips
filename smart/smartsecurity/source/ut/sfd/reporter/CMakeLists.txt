####################################################################################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(SfSecurityReporter CXX)
####################################################################################################
INCLUDE( FindPkgConfig )
SET( REPORTER_REQUIRED
  dlog
  gtest
  gmock
  libnl-3.0
)

IF(${SHOW_SMARTSECURITY_POPUP} STREQUAL "y")
  LIST(APPEND REPORTER_REQUIRED notification)
ENDIF()
pkg_check_modules( Reporter_PKGS REQUIRED ${REPORTER_REQUIRED} )

ADD_DEFINITIONS( -DDEBUG_BUILD -DUS_MODULE -DSF_TRANSPORT_NETLINK )
ADD_DEFINITIONS( -Wall -Wextra )
ADD_DEFINITIONS(-DTZ_SYS_LIB="${TZ_SYS_LIB}")

INCLUDE_DIRECTORIES( ${CMAKE_SOURCE_DIR}/internal
                     ${CMAKE_SOURCE_DIR}/source/lib/
                     ${CMAKE_SOURCE_DIR}/source/app/sfpmd/include
                     ${Reporter_PKGS_INCLUDE_DIRS})


FILE( GLOB_RECURSE TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" 
                            )
LIST( APPEND TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../main.cpp" )
# LINK_DIRECTORIES( ${CMAKE_SOURCE_DIR}/lib/cmake/ ${libnl-3.0_LIBRARIES})

ADD_EXECUTABLE(${PROJECT_NAME} ${TEST_SRC} )
TARGET_LINK_LIBRARIES( ${PROJECT_NAME} primitive transport core sfkc ${Reporter_PKGS_LDFLAGS} sfpmdTest)
INSTALL( TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${TZ_SYS_BIN}/UT )
