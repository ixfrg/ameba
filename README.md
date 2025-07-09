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
    apt-get install -y llvm linux-tools-common libbpf-dev linux-headers-$(uname -r) gcc-multilib
```

For `bpftool` installation, directly download version [v7.2.0](https://github.com/libbpf/bpftool/releases/tag/v7.2.0) and add it to your path. For more details, see the issue [here](https://github.com/xdp-project/xdp-tutorial/issues/368).

## Build & Install

```
mkdir build && \
    pushd build && \
    ../configure CC=clang --prefix=${PWD}/local-install && \
    make all && \
    make install && \
    popd
```

## See help

```
sudo local-install/bin/ameba --help
```

## Tests

Install [CppUTest](https://cpputest.github.io/manual.html): `sudo apt-get install cpputest`


# Use Cases

* Lightweight security auditing

* Research and experimentation

* System tracing and syscall monitoring