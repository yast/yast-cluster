#
# spec file for package yast2-cluster
#
# Copyright (c) 2020 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%define _fwdefdir %{_libexecdir}/firewalld/services
Name:           yast2-cluster
Version:        4.1.6
Release:        0

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2
Source1:        cluster.firewalld.xml

# Yast2::Systemd::Socket
BuildRequires:  yast2 >= 4.1.3
Requires:       yast2 >= 4.1.3

BuildRequires:  perl-XML-Writer
BuildRequires:  update-desktop-files
BuildRequires:  yast2-devtools >= 3.1.10
BuildRequires:  yast2-testsuite
BuildRequires:  firewall-macros

Requires:       yast2 >= 4.0.39
Requires:       yast2-ruby-bindings >= 1.0.0
Requires:       sharutils
BuildArch:      noarch

Summary:        Configuration of cluster
License:        GPL-2.0-only
Group:          System/YaST

%description
-

%prep
%setup -n %{name}-%{version}

%build
%yast_build

%install
%yast_install

install -D -m 0644 %{S:1} $RPM_BUILD_ROOT/%{_fwdefdir}/cluster.xml

%post
%firewalld_reload

%files
%defattr(-,root,root)
%dir %{yast_yncludedir}/cluster
%dir %{_libexecdir}/firewalld
%dir %{_fwdefdir}
%{yast_yncludedir}/cluster/*
%{yast_clientdir}/cluster.rb
%{yast_clientdir}/cluster_*.rb
%{yast_moduledir}/Cluster.*
%{yast_desktopdir}/cluster.desktop
%{yast_scrconfdir}/*.scr
%{yast_agentdir}/ag_openais
%doc %{yast_docdir}
%{_fwdefdir}/cluster.xml
%{yast_icondir}
%license COPYING

%changelog
