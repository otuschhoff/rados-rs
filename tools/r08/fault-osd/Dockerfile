FROM quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
COPY centos-stream.repo /etc/yum.repos.d/centos.repo
RUN dnf install -y iproute-tc-6.17.0-3.el9 && \
    test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' iproute-tc)" = iproute-tc-6.17.0-3.el9 && \
    dnf clean all
