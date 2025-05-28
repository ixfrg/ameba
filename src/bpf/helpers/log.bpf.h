#pragma once

#include "common/vmlinux.h"
#include <bpf/bpf_helpers.h>


// Macros
#define LOG_PREFIX "[ameba] [bpf]"
#define LOG_WARN(fmt, args...) bpf_printk("%s" "[WARN]" fmt "\n", LOG_PREFIX, ##args)
#define LOG_ERROR(fmt, args...) bpf_printk("%s" "[ERROR]" fmt "\n", LOG_PREFIX, ##args)