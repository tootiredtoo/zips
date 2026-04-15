##################################### PROJECT CMAKE SETUP START ####################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(smartsdecurity-tomato CXX)
###################################### PROJECT CMAKE SETUP END #####################################
include( FindPkgConfig )
pkg_check_modules( libtzplatform-config REQUIRED libtzplatform-config )
configure_file(smartsecurity_hawkp_atsc_all_in_one.xml.in smartsecurity_hawkp_atsc_all_in_one.xml  @ONLY)