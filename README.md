# Ameba
AMEBA (A Minimal EBPF Based Audit) is an eBPF-based Linux telemetry collection tool focused on capturing system-level audit events.

# Status
[![C/C++ CI](https://github.com/ixfrg/ameba/actions/workflows/c-cpp.yml/badge.svg?branch=main)](https://github.com/ixfrg/ameba/actions/workflows/c-cpp.yml)

# Features
* Collects system telemetry via eBPF.

* Hook into syscalls for lightweight observability.

* Minimal dependencies and footprint.

* Built with extensibility in mind.


# Project Structure
```
ameba
├── LICENSE
├── Makefile                            # Build targets
├── README.md
├── bin                                 # Binaries
└── src
    ├── bpf                             # BPF code
    │   ├── events                      # BPF hooks
    │   ├── helpers                     # BPF helpers
    ├── common                          # Headers used in BPF, and user-space code
    ├── user                            # User-space code
    │   ├── ameba.c                     # Userspace entrypoint
    │   ├── args                        # User arguments
    │   ├── jsonify                     # JSON helper
    │   └── record                      # BPF generated records serializers and writers
    └── utils                           # Misc. utilities
```

# Getting Started

## Prerequisites

* Linux kernel ≥ 6.8 (with eBPF support)

* Python 3.12

* Clang/LLVM and libbpf development libraries

## Install on Ubuntu

```
apt-get update && \
    apt-get install -y \
        llvm \
        linux-tools-common \
        libbpf-dev \
        linux-headers-$(uname -r) \
        gcc-multilib
```

For `bpftool` installation, directly download version [v7.2.0](https://github.com/libbpf/bpftool/releases/tag/v7.2.0) and add it to your path. For more details, see the issue [here](https://github.com/xdp-project/xdp-tutorial/issues/368).

## Build & Install

The configuration requires read access to the file `/sys/kernel/tracing/available_events`. By default, it can be only accessed by `root` user. To avoid configuration as `root` user, create a temporary copy of the file and delete it after configuration. The steps below show how to do that.

```
# Create and cd into build directory.
mkdir build
pushd build

# Copy the file "/sys/kernel/tracing/available_events" as root and make the copy readable to the current user.
sudo cp "/sys/kernel/tracing/available_events" "${PWD}/tmp_available_events"
sudo chown $(whoami) "${PWD}/tmp_available_events"

# Configuration
../configure \
    CC=clang \
    --prefix="${PWD}/local-install" \
    --with-path-tracing-available-events="${PWD}/tmp_available_events"

# Build & install
make all
make install

# Remove the temp file
rm "${PWD}/tmp_available_events"
```

## See help

```
pushd build
local-install/bin/ameba --help
```

# Tests

## Requirements

* [CppUTest](https://cpputest.github.io/manual.html) (On Ubuntu use `sudo apt-get install cpputest`)

## Execute

Use the following command to execute tests:
```
pushd build
make check
```

# Use Cases

* Lightweight security auditing

* Research and experimentation

* System tracing and syscall monitoring