Name:           lh-auto-remediation
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-remediate - Cryptographic Patch Verification Digest & Synthesized AST Transform
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-auto-remediation
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
Automated DevSecOps configuration remediation engine consuming SARIF v2.1.0 and JSON security findings to synthesize deterministic, SHA-256 pre-image verified unified diffs and hardening patches.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-remediate ]; then
    install -m 0755 bin/lh-remediate %{buildroot}%{_bindir}/lh-remediate
elif [ -f lh-remediate ]; then
    install -m 0755 lh-remediate %{buildroot}%{_bindir}/lh-remediate
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-auto-remediation.
