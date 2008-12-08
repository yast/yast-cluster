#
# spec file for package yast2-cluster (Version 2.15.0)
#
# norootforbuild

Name:		yast2-cluster
Version:	2.15.0
Release:	0
License:	GPL
Group:		System/YaST
BuildRoot:	%{_tmppath}/%{name}-%{version}-build
Source0:	yast2-cluster-2.15.0.tar.bz2

prefix:		/usr

Requires:	yast2
BuildRequires:	perl-XML-Writer update-desktop-files yast2 yast2-devtools yast2-testsuite

BuildArchitectures:	noarch

Summary:	Configuration of cluster

%description
-

%prep
%setup -n yast2-cluster-2.15.0

%build
%{prefix}/bin/y2tool y2autoconf
%{prefix}/bin/y2tool y2automake
autoreconf --force --install

export CFLAGS="$RPM_OPT_FLAGS -DNDEBUG"
export CXXFLAGS="$RPM_OPT_FLAGS -DNDEBUG"

%{?suse_update_config:%{suse_update_config -f}}
./configure --libdir=%{_libdir} --prefix=%{prefix} --mandir=%{_mandir}
make %{?jobs:-j%jobs}

%install
make install DESTDIR="$RPM_BUILD_ROOT"
[ -e "%{prefix}/share/YaST2/data/devtools/NO_MAKE_CHECK" ] || Y2DIR="$RPM_BUILD_ROOT/usr/share/YaST2" make check DESTDIR="$RPM_BUILD_ROOT"
for f in `find $RPM_BUILD_ROOT/%{prefix}/share/applications/YaST2/ -name "*.desktop"` ; do
    d=${f##*/}
    %suse_update_desktop_file -d ycc_${d%.desktop} ${d%.desktop}
done


%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(-,root,root)
%dir /usr/share/YaST2/include/cluster
/usr/share/YaST2/include/cluster/*
/usr/share/YaST2/clients/cluster.ycp
/usr/share/YaST2/clients/cluster_*.ycp
/usr/share/YaST2/modules/Cluster.*
/usr/share/YaST2/modules/Cluster2.*
/usr/share/YaST2/modules/Cluster3.py
/usr/share/YaST2/scrconf/openais.scr
%{prefix}/share/applications/YaST2/cluster.desktop
%{prefix}/lib/YaST2/servers_non_y2/ag_openais
%doc %{prefix}/share/doc/packages/yast2-cluster
