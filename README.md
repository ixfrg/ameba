# Ameba
AMEBA (A Minimal EBPF Based Audit) is an eBPF-based Linux telemetry collection tool focused on capturing system-level audit events.


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

## Build

```
make all
```

## See help

```
sudo ./bin/ameba --help
```

# Use Cases

* Lightweight security auditing

* Research and experimentation

* System tracing and syscall monitoring