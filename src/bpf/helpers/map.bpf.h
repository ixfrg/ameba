#pragma once

#include "common/vmlinux.h"
#include "common/types.h"


#define MAPS_HASH_MAP_MAX_ENTRIES 1024

// structs
struct map_key_process_record
{
    pid_t pid;
    record_type_t record_type;
};

long map_init_map_key_process_record(
    struct map_key_process_record *map_key,
    pid_t pid, record_type_t record_type 
);