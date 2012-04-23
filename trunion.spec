%define pyver 26
%define name python%{pyver}-trunion
%define pythonname trunion
%define version 1.0
%define release 1

Summary: Receipt Signing App
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{pythonname}-%{version}.tar.gz
License: MPL
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{pythonname}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Services team <services-dev@mozilla.org>
Requires: python%{pyver} python%{pyver}-setuptools python%{pyver}-webob python%{pyver}-paste
Requires: python%{pyver}-pastedeploy python%{pyver}-pyramid python%{pyver}-simplejson
Requires: python%{pyver}-m2crypto python%{pyver}-cef

Url: https://github.com/rtilder/trunion

%description
See README

%prep
%setup -n %{pythonname}-%{version} -n %{pythonname}-%{version}

%build
python2.6 setup.py build

%install
python2.6 setup.py install --single-version-externally-managed --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES

%defattr(-,root,root)
