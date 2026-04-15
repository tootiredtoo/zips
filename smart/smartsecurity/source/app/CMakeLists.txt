#CMAKE system version requirement
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Add applications to the build schedule
ADD_SUBDIRECTORY(sfpmd)
IF(SMARTSECURITY_CONTROLLER)
  ADD_SUBDIRECTORY(controller)
ENDIF()
