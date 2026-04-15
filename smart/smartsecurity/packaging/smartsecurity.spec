################################## DESCRIPTION SECTION START #######################################
Name:           smartsecurity2
Summary:        Smart Security TV subsystem
Version:        5.0.9
Release:        0
ExclusiveArch:  %arm aarch64
Group:          System/Security
License:        Apache 2.0
Source0:        smartsecurity2-%{version}.tar.gz
BuildRequires:  pkgconfig(libnl-3.0)
%description
Smart Security (Add description)
################################### DESCRIPTION SECTION END ########################################

BuildRequires: pkgconfig(libtzplatform-config)

%{?!sfpmd_plugin: %define sfpmd_plugin y}
%{?!sec_buildconf_product_lite_tizen: %define sec_buildconf_product_lite_tizen n}
%{?!sfpmd_controller_build: %define sfpmd_controller_build n}
%define SHOW_SMARTSECURITY_POPUP N

##################################### PACKAGE SECTION START ########################################
%package        devel
Summary:        Smart Security 2 (Add description)
Group:          Development/Libraries
Provides:       Libraries
Requires:       smartsecurity2
%description    devel
Smart Seurity 2 devel (Add description)

####################################################################################################
%package        sfpmd
Summary:        Smart Security 2 Plugin Monitor Daemon
Provides:       binary
BuildRequires:  pkgconfig(sid)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(jsoncpp)
BuildRequires:  pkgconfig(deviced)
BuildRequires:  pkgconfig(capi-appfw-application)
BuildRequires:  pkgconfig(capi-network-connection)
BuildRequires:  pkgconfig(capi-system-usbdevice)
BuildRequires:  pkgconfig(model-config)
%if (%{SHOW_SMARTSECURITY_POPUP} == "y")
BuildRequires:  pkgconfig(notification)
%endif
BuildRequires:  gettext-devel
%if (%{sec_buildconf_product_lite_tizen} == "n")
BuildRequires:  scs-common-client-devel
BuildRequires:  pkgconfig(scs-common-client)
BuildRequires:  pkgconfig(smart-deadlock)
%endif
%description    sfpmd
Smart Security 2 Plugin Monitor Daemon

####################################################################################################
%package        controller
Summary:        UI application to control and manage Smart Security
Group:          TO_BE/FILLED_IN
Requires:       smartsecurity2

%if (%{sfpmd_controller_build} == "y")

BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(ui-gadget-1)
BuildRequires:  pkgconfig(vd-win-util)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(menu-plugin-loader) 
BuildRequires:  pkgconfig(jsoncpp)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(capi-appfw-application)
BuildRequires:  pkgconfig(uifw_misc)
BuildRequires:  pkgconfig(efl-assist)
BuildRequires:  pkgconfig(capi-ui-efl-util)
BuildRequires:  edje-bin
BuildRequires:  gettext-devel
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(capi-system-usbdevice)
BuildRequires:  pkgconfig(notification)
BuildRequires:  com.samsung.tv.theme-resource-NOTIFICATION
%if %{_vd_cfg_product_type} != "AUDIO"
BuildRequires:  pkgconfig(voice-control-elm)
%define NoAudio 1
%else
%define NoAudio 0
%endif
%define SF_RESOURCE_FROM /opt/usr/apps/com.samsung.tv.theme-resource/shared/res/NOTIFICATION
%define SF_RESOURCE_DEST /usr/apps/com.samsung.tv.theme-resource/shared/res/org.tizen.smart_security

%description controller
TV Smart Security Application for Tizen TV.

%else # %{sfpmd_controller_build} == "y"

%description controller
TV Smart Security Application for Tizen TV. TODO : Redundant package

%endif


####################################################################################################
%package theme-resource
Summary:  Notification resource files

%description theme-resource
Notification resource files

####################################################################################################
%package        ut
Summary:        Unit tests for smartsecurity
Provides:       binary
Group:          TO_BE/FILLED_IN
Requires:       smartsecurity2
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  gtest-devel
%description    ut
Unit tests for smartsecurity2

%{?!TOMATO: %define TOMATO n}
%if %{TOMATO} == "y"
%define _tcdir %{TZ_SYS_RW_APP}/tomato/testcase/%{name}-func-tomato/tc

####################################################################################################
%package func-tomato
BuildRequires:  pkgconfig(tomato)
Summary: Test package for TOMATO
Requires: %{name} = %{version}-%{release}
BuildRequires: pkgconfig(libtzplatform-config)
%description func-tomato
This package is for TOMATO TC
%endif

###################################### PACKAGE SECTION END #########################################

##################################### DEFINES SECTION START ########################################
%define _jsonresdir %{TZ_SYS_RW_APP}/org.tizen.smart_security/shared/
###################################### DEFINES SECTION END #########################################

##################################### PRERAPE SECTION START ########################################
%prep
%setup -q

cd -
###################################### PRERAPE SECTION END #########################################

###################################### BUILD SECTION START #########################################
%build

%if ("%{vdut}" == "=c")
source ~/.bash_profile
%define _covfile %{name}-ut.cov
export COVFILE=~/%{_covfile}
cov01 -1
%endif

%if ( %{_vd_cfg_product_type} == "WALL" )
    %define THEWALL_SUPPORT Y
%else
    %define THEWALL_SUPPORT N
%endif


%define BUILD_TESTS TRUE

%define TZ_SYS_LIB %{_libdir}
echo "TZ_SYS_LIB : %{TZ_SYS_LIB}"

export CFLAGS="$CFLAGS -O2 -Wall -Wno-deprecated-declarations -Wcast-align -fPIC -fPIE -pie -Wcast-qual -Wextra -Wno-unused-parameter \
        	   -Wshadow -Wno-write-strings -fno-common -fno-omit-frame-pointer \
        	   -fno-optimize-sibling-calls -fno-strict-aliasing -fsigned-char -fstrict-overflow \
               -Wno-ignored-qualifiers -Wno-array-bounds -Wno-empty-body -Wformat-extra-args \
               -fstack-protector-strong -Wl,-z,relro -D_FORTIFY_SOURCE=2" 

export CXXFLAGS="$CXXFLAGS -O2 -Wall -Wno-deprecated-declarations -Wcast-align -fPIC -fPIE -pie -Wcast-qual -Wextra -Wnon-virtual-dtor \
                 -Wno-unused-parameter -Wshadow -Wno-write-strings -fno-omit-frame-pointer \
                 -fno-optimize-sibling-calls -fno-strict-aliasing -fsigned-char -fstrict-overflow \
                 -Wno-ignored-qualifiers -Wno-c++0x-compat -Wno-array-bounds -Wno-empty-body -Wformat-extra-args \
                 -fstack-protector-strong -Wl,-z,relro -D_FORTIFY_SOURCE=2" 
#
export LDFLAGS="${LDFLAGS} -Wl,--rpath=${PREFIX}/lib -Wl,--as-needed -Wl,--hash-style=both"
export SF_CONTROLLER_PREFIX="%{TZ_SYS_RO_APP}/org.tizen.smart_security"

# TOMATO adding build script >>>>> START
%if %{TOMATO} == "y"
%cmake . -DDEBUG_BUILD=TRUE \
         -DCMAKE_INSTALL_PREFIX="${SF_CONTROLLER_PREFIX}" \
         -DVERSION="%{version}" \
         -DMANIFESTDIR="%{TZ_SYS_RO_SHARE}/packages/" \
         -DBUILD_TESTS=%{BUILD_TESTS} \
         -DLOCALEDIR="${SF_CONTROLLER_PREFIX}/shared/locale/" \
         -DPACKAGE_NAME="org.tizen.smart_security" \
         -DINCLUDE_INSTALL_DIR=%{_includedir}/smartsecurity2 \
         -DTOMATO=%{TOMATO} -DTCDIR=%{_tcdir} \
         -DTZ_SYS_RO_APP="%{TZ_SYS_RO_APP}" \
         -DTZ_SYS_RW_APP="%{TZ_SYS_RW_APP}" \
         -DTZ_SYS_BIN="%{TZ_SYS_BIN}" \
         -DTZ_SYS_RO_SHARE="%{TZ_SYS_RO_SHARE}" \
         -DTZ_SYS_RO_UG="%{TZ_SYS_RO_UG}" \
         -DNOAUDIO="%{NoAudio}" \
         -DTHEWALL_SUPPORT="%{THEWALL_SUPPORT}" \
         -DIS_TIZEN_LITE="%{sec_buildconf_product_lite_tizen}" \
         -DSHOW_SMARTSECURITY_POPUP="%{SHOW_SMARTSECURITY_POPUP}" \
	 -DSMARTSECURITY_CONTROLLER="%{sfpmd_controller_build}" \
         -DTZ_SYS_LIB="%{TZ_SYS_LIB}"
%else
%cmake . -DDEBUG_BUILD=TRUE \
         -DCMAKE_INSTALL_PREFIX="${SF_CONTROLLER_PREFIX}" \
         -DVERSION="%{version}" \
         -DMANIFESTDIR="%{TZ_SYS_RO_SHARE}/packages/" \
         -DBUILD_TESTS=%{BUILD_TESTS} \
         -DLOCALEDIR="${SF_CONTROLLER_PREFIX}/shared/locale/" \
         -DPACKAGE_NAME="org.tizen.smart_security" \
         -DINCLUDE_INSTALL_DIR=%{_includedir}/smartsecurity2 \
         -DTZ_SYS_RO_APP="%{TZ_SYS_RO_APP}" \
         -DTZ_SYS_RW_APP="%{TZ_SYS_RW_APP}" \
         -DTZ_SYS_BIN="%{TZ_SYS_BIN}" \
         -DTZ_SYS_RO_SHARE="%{TZ_SYS_RO_SHARE}" \
         -DTZ_SYS_RO_UG="%{TZ_SYS_RO_UG}" \
         -DNOAUDIO="%{NoAudio}" \
         -DTHEWALL_SUPPORT="%{THEWALL_SUPPORT}" \
         -DIS_TIZEN_LITE="%{sec_buildconf_product_lite_tizen}" \
         -DSHOW_SMARTSECURITY_POPUP="%{SHOW_SMARTSECURITY_POPUP}" \
	 -DSMARTSECURITY_CONTROLLER="%{sfpmd_controller_build}" \
         -DTZ_SYS_LIB="%{TZ_SYS_LIB}"
%endif
# TOMATO adding build script >>>>> STOP
#

make %{?jobs:-j%jobs}
####################################### BUILD SECTION END ##########################################

##################################### INSTALL SECTION START ########################################
%install
rm -rf %{buildroot}
%make_install
%if ("%{sfpmd_plugin}" == "n")
# Service
mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
install -m 644 source/app/sfpmd/sfpmd.service %{buildroot}/usr/lib/systemd/system/sfpmd.service
mkdir -p %{buildroot}/usr/lib/systemd/system/user
ln -s ../sfpmd.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/sfpmd.service
%endif
mkdir -p %{buildroot}%{_libdir}/Plugins
mkdir -p %{buildroot}/%{_jsonresdir}
%if (%{sfpmd_controller_build} == "y")
# image
mkdir -p %{buildroot}/%{SF_RESOURCE_DEST}
cp -rf  %{SF_RESOURCE_FROM}/notification_icon_security.svg %{buildroot}/%{SF_RESOURCE_DEST}
%endif
# TOMATO  >>>>> START
%if %{TOMATO} == "y"
    mkdir -p %{buildroot}%{_tcdir}
    cp -f tomato/tc/smartsecurity_hawkp_atsc_all_in_one.xml %{buildroot}%{_tcdir}
    cp -f tomato/tc/TCList.dat %{buildroot}%{_tcdir}
%endif
# TOMATO  >>>>> STOP

###################################### INSTALL SECTION END #########################################

################################### POSTINSTALL SECTION START ######################################
%post -n smartsecurity2

%if (%{sfpmd_controller_build} == "y")
####################################################################################################
%post -n smartsecurity2-controller
mkdir -p %{TZ_SYS_RW_APP}/org.tizen.smart_security/data/report
chsmack -a "_" -t %{TZ_SYS_RW_APP}/org.tizen.smart_security/
%endif

%if ("%{sfpmd_plugin}" == "n")
####################################################################################################
%post -n smartsecurity2-sfpmd
systemctl daemon-reload
systemctl enable sfpmd.service
systemctl start sfpmd.service
%endif

%if (%{sfpmd_controller_build} == "y")
####################################################################################################
%post theme-resource
chsmack -a User::Home %{SF_RESOURCE_DEST}/*
%endif
#################################### POSTINSTALL SECTION END #######################################

################################## POSTUNINSTALL SECTION START #####################################
%postun -n smartsecurity2

%if (%{sfpmd_controller_build} == "y")
####################################################################################################
%postun -n smartsecurity2-controller
rm -rf %{TZ_SYS_RW_APP}/org.tizen.smart_security
%endif
####################################################################################################
%postun -n smartsecurity2-sfpmd
systemctl daemon-reload
systemctl stop sfpmd.service

################################### POSTUNINSTALL SECTION END ######################################

###################################### FILES SECTION START #########################################
%files devel
%defattr(-,root,root,-)
%{_includedir}/*

####################################################################################################
%files
%manifest org.tizen.smart_security.manifest
%defattr(-,root,root,-)
%{_libdir}/libcore.so
%{_libdir}/libprimitive.so
%{_libdir}/libprotocol.so
%{_libdir}/libtransport.so
%{_libdir}/libsfkc.so
%{_libdir}/Plugins/

####################################################################################################
%files sfpmd
%manifest smartsecurity_module.manifest
%defattr(-,root,root,-)
%if ("%{sfpmd_plugin}" == "y")
/usr/share/security-solution-daemon/plugins/libsfpmd-plugin.so
%else
%{_bindir}/sfpmd
/usr/lib/systemd/system/sfpmd.service
/usr/lib/systemd/system/multi-user.target.wants/sfpmd.service
%endif

####################################################################################################
%files controller
%manifest smartsecurity_module.manifest
%defattr(-,root,root,-)
%if (%{sfpmd_controller_build} == "y")
%{TZ_SYS_RO_APP}/org.tizen.smart_security/bin/smart_security
%{TZ_SYS_RO_APP}/org.tizen.smart_security/shared/*
%{TZ_SYS_RO_SHARE}/packages/*.xml
%endif
####################################################################################################
%files theme-resource
%if (%{sfpmd_controller_build} == "y")
%{SF_RESOURCE_DEST}/*
%endif
%defattr(-,root,root,-)

####################################################################################################
%if (%{BUILD_TESTS} == "TRUE")
%files ut
%manifest smartsecurity_module.manifest
%defattr(-,root,root,-)
%{_bindir}/UT/* 
%endif

####################################################################################################
%if (%{TOMATO} == "y")
%files func-tomato
%defattr(-,root,root,-)
%{_tcdir}/*
%endif

####################################### FILES SECTION END ##########################################

###################################### CLEAN SECTION START #########################################
%clean
pwd

%if ("%{vdut}" == "=c")
mv ~/%{_covfile} ~/rpmbuild/RPMS/armv7l/
echo %{_covfile} > ~/rpmbuild/RPMS/armv7l/covfile.txt
%endif

rm -rf CMakeCache.txt CMakeFiles cmake_install.cmake Makefile install_manifest.txt
rm -rf *.pc *.so *.so.* sfpmd
####################################### CLEAN SECTION END ##########################################
