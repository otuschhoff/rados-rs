ARG CEPH_IMAGE=quay.io/ceph/ceph@sha256:6bb1c8a42fbc0bf87938946990b65174466997bc11c31eb5a323225a779fd8f9
FROM ${CEPH_IMAGE} AS build
ARG COMPILER_PACKAGE=gcc-c++-11.5.0-15.el9
ARG CEPH_DEVEL_PACKAGE=librados-devel-20.2.4-0.el9
ARG CEPHPP_DEVEL_PACKAGE=libradospp-devel-20.2.4-0.el9
ARG CEPH_DEVEL_REPOSITORY=https://download.ceph.com/rpm-20.2.4/el9
ARG CEPH_DEVEL_AMD64_SHA256=5a8d9defce5f81634e52ad383aec7257156d355ad23a94fffc0d8df58314e195
ARG CEPH_DEVEL_ARM64_SHA256=8099805cc647054564b93231680c21ea1c7a8e7d7912ecdd706374e32fe56417
ARG CEPHPP_DEVEL_AMD64_SHA256=e6b4af18428d87fcb6913bee11449d88fc956ead2f17cb1426b086e310b93e7a
ARG CEPHPP_DEVEL_ARM64_SHA256=3344fc0a7a5d66a65da1bbd4d6b815b72a7e6b290aaccc5358dae32637c85f76
ARG TARGETARCH
COPY centos-stream.repo /etc/yum.repos.d/centos.repo
RUN case "${TARGETARCH}" in \
			amd64) rpm_arch=x86_64; c_checksum="${CEPH_DEVEL_AMD64_SHA256}"; cpp_checksum="${CEPHPP_DEVEL_AMD64_SHA256}" ;; \
			arm64) rpm_arch=aarch64; c_checksum="${CEPH_DEVEL_ARM64_SHA256}"; cpp_checksum="${CEPHPP_DEVEL_ARM64_SHA256}" ;; \
			*) echo "unsupported oracle architecture: ${TARGETARCH}" >&2; exit 2 ;; \
		esac && \
		c_rpm="/tmp/${CEPH_DEVEL_PACKAGE}.${rpm_arch}.rpm" && \
		cpp_rpm="/tmp/${CEPHPP_DEVEL_PACKAGE}.${rpm_arch}.rpm" && \
		curl -fsSL "${CEPH_DEVEL_REPOSITORY}/${rpm_arch}/${CEPH_DEVEL_PACKAGE}.${rpm_arch}.rpm" -o "${c_rpm}" && \
		curl -fsSL "${CEPH_DEVEL_REPOSITORY}/${rpm_arch}/${CEPHPP_DEVEL_PACKAGE}.${rpm_arch}.rpm" -o "${cpp_rpm}" && \
		echo "${c_checksum}  ${c_rpm}" | sha256sum -c - && \
		echo "${cpp_checksum}  ${cpp_rpm}" | sha256sum -c - && \
		dnf -y install "${c_rpm}" "${cpp_rpm}" "${COMPILER_PACKAGE}" && \
		test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' librados-devel)" = "${CEPH_DEVEL_PACKAGE}" && \
		test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' libradospp-devel)" = "${CEPHPP_DEVEL_PACKAGE}" && \
		rm -f "${c_rpm}" "${cpp_rpm}" && dnf clean all
COPY main.cc /src/main.cc
RUN c++ -std=c++17 -O2 -Wall -Wextra -Werror /src/main.cc -lrados -o /rados-reference

FROM ${CEPH_IMAGE}
ARG LIBRADOS_PACKAGE=librados2-20.2.4-0.el9
LABEL ceph="False"
RUN test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' librados2)" = "${LIBRADOS_PACKAGE}"
COPY --from=build /rados-reference /usr/local/bin/rados-reference
ENTRYPOINT ["/usr/local/bin/rados-reference"]