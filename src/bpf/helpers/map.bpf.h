#pragma once

/*

    A module for defining helper functions for working with BPF maps.

*/

#include "common/vmlinux.h"
#include "common/types.h"


/*
    Max entries in BPF map of type hash map.
    Arbitrarily selected.
*/
#define MAPS_HASH_MAP_MAX_ENTRIES 1024
