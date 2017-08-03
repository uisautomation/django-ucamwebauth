Name: django-ucamwebauth
Version: 1.4.4
Release: 1
Summary: University of Cambridge Web Authentication module for Django
Source: %{name}-%{version}.tar.gz
Group: Unknown
License: None
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildArch: noarch
BuildRequires: python-setuptools

Requires: python-Django >= 1.8 python-openssl >= 0.11

%Description
This package provides a django authentication back-end to the
University of Cambridge Web Authentication system.

%Prep
%setup

%Build
python setup.py build

%Install
python setup.py install -O1 --prefix=%{_prefix} --root="${RPM_BUILD_ROOT}" --record=INSTALLED_FILES

%Clean
rm -rf "${RPM_BUILD_ROOT}"

%Files -f INSTALLED_FILES
%defattr(-,root,root)
