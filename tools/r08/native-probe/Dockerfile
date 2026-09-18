FROM quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa AS build
ARG TARGETARCH
COPY centos-stream.repo /etc/yum.repos.d/centos.repo
RUN case "${TARGETARCH}" in \
			amd64) rpm_arch=x86_64; c_checksum=5a8d9defce5f81634e52ad383aec7257156d355ad23a94fffc0d8df58314e195; cpp_checksum=e6b4af18428d87fcb6913bee11449d88fc956ead2f17cb1426b086e310b93e7a ;; \
			arm64) rpm_arch=aarch64; c_checksum=8099805cc647054564b93231680c21ea1c7a8e7d7912ecdd706374e32fe56417; cpp_checksum=3344fc0a7a5d66a65da1bbd4d6b815b72a7e6b290aaccc5358dae32637c85f76 ;; \
			*) exit 2 ;; \
		esac && \
		base=https://download.ceph.com/rpm-20.2.4/el9/${rpm_arch} && \
		curl -fsSL "$base/librados-devel-20.2.4-0.el9.${rpm_arch}.rpm" -o /tmp/librados-devel.rpm && \
		curl -fsSL "$base/libradospp-devel-20.2.4-0.el9.${rpm_arch}.rpm" -o /tmp/libradospp-devel.rpm && \
		echo "$c_checksum  /tmp/librados-devel.rpm" | sha256sum -c - && \
		echo "$cpp_checksum  /tmp/libradospp-devel.rpm" | sha256sum -c - && \
		dnf install -y gcc-c++-11.5.0-15.el9 /tmp/librados-devel.rpm /tmp/libradospp-devel.rpm && \
		dnf clean all
COPY probe.cpp /src/probe.cpp
RUN g++ -std=c++17 -O2 -Wall -Wextra -Werror -o /rados-r08-native /src/probe.cpp -lrados

FROM quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
RUN test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' librados2)" = librados2-20.2.4-0.el9
COPY --from=build /rados-r08-native /usr/local/bin/rados-r08-native