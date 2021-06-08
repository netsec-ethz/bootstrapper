Name: scion-bootstrapper
Version: devel
Release: 1
Summary: SCION Endhost Bootstrapper
URL: https://www.scion-architecture.net
License: Apache License, v2.0

Source0: bazel-out/k8-fastbuild/bin/scion-bootstrapper.tar.gz

Requires: libcap
Requires: scion-daemon
Requires: scion-dispatcher

%description
SCION Bootstrapper

%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

%prep
ls -l bazel-out/k8-fastbuild/bin/

%build
tar xvf bazel-out/k8-fastbuild/bin/scion-bootstrapper.tar.gz

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}%{_bindir}/
install -m 755 ./usr/bin/bootstrapper %{buildroot}%{_bindir}/bootstrapper

#mkdir -p %{buildroot}%{_unitdir}/
mkdir -p %{buildroot}/lib/systemd/system/
cp ./lib/systemd/system/scion-bootstrapper@.service %{buildroot}/lib/systemd/system/scion-bootstrapper@.service

mkdir -p %{buildroot}/etc/scion/
cp ./etc/scion/bootstrapper.toml %{buildroot}/etc/scion/bootstrapper.toml

mkdir -p %{buildroot}%{_sysconfdir}/scion

%clean
rm -rf %{buildroot}

%files
%attr(0755, root, root) %{_bindir}/bootstrapper
%attr(0644, root, root) /lib/systemd/system/scion-bootstrapper@.service
%attr(0644, scion, scion) /etc/scion/bootstrapper.toml
