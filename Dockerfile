FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG QEMU_REPOSITORY=https://gitlab.com/qemu-project/qemu.git
ARG QEMU_COMMIT=562bae590f194fb590beb5c65da44fc35ab9f64a

LABEL org.opencontainers.image.title="QEMU CXL mailbox RCE validation lab" \
      org.opencontainers.image.description="Docker-bounded reproduction of C25-f plus C32-a against a pinned QEMU revision" \
      org.opencontainers.image.revision="${QEMU_COMMIT}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        binutils \
        build-essential \
        ca-certificates \
        file \
        git \
        libaio-dev \
        libattr1-dev \
        libcap-ng-dev \
        libfdt-dev \
        libglib2.0-dev \
        libpixman-1-dev \
        libslirp-dev \
        ninja-build \
        pkg-config \
        python3 \
        python3-venv \
        tar \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git init /opt/qemu-src \
    && git -C /opt/qemu-src remote add origin "${QEMU_REPOSITORY}" \
    && git -C /opt/qemu-src fetch --depth=1 origin "${QEMU_COMMIT}" \
    && git -C /opt/qemu-src checkout --detach FETCH_HEAD \
    && test "$(git -C /opt/qemu-src rev-parse HEAD)" = "${QEMU_COMMIT}" \
    && git -C /opt/qemu-src submodule update --init --depth=1

RUN mkdir -p /opt/qemu-build \
    && cd /opt/qemu-build \
    && /opt/qemu-src/configure \
        --target-list=x86_64-softmmu \
        --disable-asan \
        --disable-debug-info \
        --disable-docs \
        --disable-seccomp \
        --disable-tsan \
        --disable-ubsan \
        --disable-werror \
        --enable-pie \
        --extra-cflags=-O2 \
    && ninja qemu-system-x86_64

COPY tools/cxl-layout-probe.c /tmp/cxl-layout-probe.c

RUN cc -m64 \
        -I/opt/qemu-build \
        -I/opt/qemu-src \
        -I/usr/include/pixman-1 \
        -I/usr/include/glib-2.0 \
        -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
        -I/usr/include/libmount \
        -I/usr/include/blkid \
        -I/usr/include/gio-unix-2.0 \
        -isystem /opt/qemu-src/linux-headers \
        -isystem /opt/qemu-build/linux-headers \
        -iquote /opt/qemu-build \
        -iquote /opt/qemu-src \
        -iquote /opt/qemu-src/include \
        -iquote /opt/qemu-src/host/include/x86_64 \
        -iquote /opt/qemu-src/host/include/generic \
        -pthread \
        -fPIE \
        -D_DEFAULT_SOURCE \
        -D_XOPEN_SOURCE=600 \
        -DCONFIG_SOFTMMU \
        -DCOMPILING_SYSTEM_VS_USER \
        /tmp/cxl-layout-probe.c \
        -o /opt/qemu-build/cxl-layout-probe

WORKDIR /lab

COPY scripts/make-profile.py /lab/scripts/make-profile.py

RUN python3 /lab/scripts/make-profile.py \
        --qemu /opt/qemu-build/qemu-system-x86_64 \
        --layout-probe /opt/qemu-build/cxl-layout-probe \
        --source /opt/qemu-src \
        --expected-commit "${QEMU_COMMIT}" \
        --output /opt/qemu-build/profile-build.json

COPY poc /lab/poc
COPY scripts /lab/scripts

RUN chmod 0555 \
        /lab/poc/cxl_mailbox_rce.py \
        /lab/scripts/make-profile.py \
        /lab/scripts/run-lab.sh

ENV TMPDIR=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    LAB_CONTAINER=1 \
    QEMU_COMMIT=${QEMU_COMMIT}

ENTRYPOINT ["/lab/scripts/run-lab.sh"]
